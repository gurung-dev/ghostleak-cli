"""Exposure score, risk tier, and the local Machine Ghost ID.

The weights below are the whole scoring model. Findings reference a code in
this table. The published total is the sum of finding points, capped at 100.

Tiers
    0–24   LOW
    25–49  MODERATE
    50–74  HIGH
    75–100 CRITICAL
"""

from __future__ import annotations

import hashlib
import platform
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ghostleak.parsers import format_endpoint, is_routable, is_vpn_iface

WEIGHTS = [
    {
        "code": "wildcard_listener",
        "points": 8,
        "cap": 24,
        "summary": "TCP/UDP socket bound to 0.0.0.0, ::, or *",
    },
    {
        "code": "interface_listener",
        "points": 3,
        "cap": 9,
        "summary": "Socket bound to a specific non-loopback address",
    },
    {
        "code": "no_vpn",
        "points": 6,
        "cap": 6,
        "summary": "Routable interface present and no VPN/tunnel interface",
    },
    {
        "code": "sensitive_env",
        "points": 3,
        "cap": 15,
        "summary": "Sensitive environment variable name is set (value is never stored)",
    },
    {
        "code": "ssh_world_readable",
        "points": 12,
        "cap": 12,
        "summary": "SSH directory or private key is world-readable or world-writable",
    },
    {
        "code": "ssh_permissive",
        "points": 6,
        "cap": 12,
        "summary": "SSH directory or private key is group-readable",
    },
    {
        "code": "history_world_readable",
        "points": 8,
        "cap": 8,
        "summary": "Shell history file is world-readable or world-writable",
    },
    {
        "code": "history_group_readable",
        "points": 4,
        "cap": 8,
        "summary": "Shell history file is group-readable",
    },
    {
        "code": "secret_file_exposed",
        "points": 10,
        "cap": 20,
        "summary": "Credential file is world-readable or world-writable",
    },
    {
        "code": "secret_file_group",
        "points": 5,
        "cap": 10,
        "summary": "Credential file is group-readable",
    },
    {
        "code": "config_world_writable",
        "points": 6,
        "cap": 12,
        "summary": "Shell startup file is world-writable",
    },
    {
        "code": "firewall_off",
        "points": 15,
        "cap": 15,
        "summary": "Host firewall reports that it is inactive",
    },
    {
        "code": "firewall_unknown",
        "points": 4,
        "cap": 4,
        "summary": "Host firewall state could not be read",
    },
    {
        "code": "running_as_root",
        "points": 12,
        "cap": 12,
        "summary": "The scan is running as root",
    },
    {
        "code": "browser_no_privacy",
        "points": 3,
        "cap": 9,
        "summary": "Installed browser has no detected privacy extension or user.js",
    },
]

TIERS = [
    {"tier": "LOW", "min": 0, "max": 24},
    {"tier": "MODERATE", "min": 25, "max": 49},
    {"tier": "HIGH", "min": 50, "max": 74},
    {"tier": "CRITICAL", "min": 75, "max": 100},
]

_WEIGHT_BY_CODE = {row["code"]: row for row in WEIGHTS}


@dataclass
class Finding:
    code: str
    severity: str
    points: int
    params: Dict[str, object] = field(default_factory=dict)


def severity_for(points: int) -> str:
    if points >= 20:
        return "critical"
    if points >= 12:
        return "high"
    if points >= 6:
        return "moderate"
    if points >= 1:
        return "low"
    return "info"


def scaled_points(code: str, count: int) -> int:
    row = _WEIGHT_BY_CODE[code]
    if count <= 0:
        return 0
    return min(row["points"] * count, row["cap"])


def exposure_score(findings: Sequence[Finding]) -> int:
    total = 0
    for finding in findings:
        try:
            total += max(0, int(finding.points))
        except (TypeError, ValueError):
            continue
    if total < 0:
        return 0
    if total > 100:
        return 100
    return total


def risk_tier(score: int) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        value = 0
    if value < 0:
        value = 0
    if value > 100:
        value = 100
    if value <= 24:
        return "LOW"
    if value <= 49:
        return "MODERATE"
    if value <= 74:
        return "HIGH"
    return "CRITICAL"


def _examples(listeners: Sequence[dict], limit: int = 5) -> str:
    bits = []
    for item in list(listeners)[:limit]:
        proto = item.get("proto") or "tcp"
        addr = item.get("addr")
        port = item.get("port")
        bits.append(f"{proto}/{format_endpoint(addr, port)}")
    extra = len(listeners) - len(bits)
    text = ", ".join(bits)
    if extra > 0:
        text += f" (+{extra})"
    return text


def _join_paths(items: Sequence[dict], limit: int = 8) -> str:
    labels = []
    for item in list(items)[:limit]:
        path = item.get("path") or "?"
        mode = item.get("mode")
        if mode:
            labels.append(f"{path} ({mode})")
        else:
            labels.append(str(path))
    extra = len(items) - len(labels)
    text = ", ".join(labels)
    if extra > 0:
        text += f" (+{extra})"
    return text


def _world(item: dict) -> bool:
    return bool(item.get("world_readable") or item.get("world_writable"))


def _add(findings: List[Finding], code: str, count: int, params: dict) -> None:
    points = scaled_points(code, count)
    if points <= 0 and count <= 0:
        return
    findings.append(
        Finding(code=code, severity=severity_for(points), points=points, params=params)
    )


def analyze(sections: dict) -> List[Finding]:
    """Turn probe dictionaries into scored findings. Pure function."""
    sections = sections or {}
    os_info = sections.get("os") or {}
    network = sections.get("network") or {}
    ports = sections.get("ports") or {}
    env = sections.get("env") or {}
    firewall = sections.get("firewall") or {}
    browser = sections.get("browser") or {}
    findings: List[Finding] = []

    listeners = list(ports.get("listeners") or [])
    wild = [item for item in listeners if (item.get("scope") or "") == "wildcard"]
    bound = [item for item in listeners if (item.get("scope") or "") == "address"]
    if wild:
        _add(
            findings,
            "wildcard_listener",
            len(wild),
            {"count": len(wild), "examples": _examples(wild)},
        )
    if bound:
        _add(
            findings,
            "interface_listener",
            len(bound),
            {"count": len(bound), "examples": _examples(bound)},
        )

    vpn_names = set()
    for name in network.get("vpn_interfaces") or []:
        if name:
            vpn_names.add(str(name))
    routable = False
    for iface in network.get("interfaces") or []:
        name = str(iface.get("name") or "")
        if is_vpn_iface(name):
            vpn_names.add(name)
            continue
        for addr in iface.get("addresses") or []:
            if is_routable(str(addr)):
                routable = True
    if network.get("status") == "ok" and routable and not vpn_names:
        _add(findings, "no_vpn", 1, {})

    sensitive = list(env.get("sensitive") or [])
    if sensitive:
        names = [str(item.get("name")) for item in sensitive if item.get("name")]
        shown = ", ".join(names[:10])
        extra = len(names) - min(len(names), 10)
        if extra > 0:
            shown += f" (+{extra})"
        _add(
            findings,
            "sensitive_env",
            len(names),
            {"count": len(names), "names": shown},
        )

    ssh = env.get("ssh") or {}
    if ssh.get("present"):
        world = []
        group = []
        if _world(ssh):
            world.append(ssh)
        elif ssh.get("group_readable"):
            group.append(ssh)
        for key in ssh.get("keys") or []:
            if _world(key):
                world.append(key)
            elif key.get("group_readable"):
                group.append(key)
        if world:
            _add(
                findings,
                "ssh_world_readable",
                1,
                {"paths": _join_paths(world), "mode": world[0].get("mode") or ""},
            )
        elif group:
            _add(
                findings,
                "ssh_permissive",
                1,
                {"paths": _join_paths(group), "mode": group[0].get("mode") or ""},
            )

    histories = [item for item in (env.get("histories") or []) if item.get("present")]
    world_hist = [item for item in histories if _world(item)]
    group_hist = [
        item for item in histories if item.get("group_readable") and item not in world_hist
    ]
    if world_hist:
        _add(
            findings,
            "history_world_readable",
            1,
            {"paths": _join_paths(world_hist)},
        )
    elif group_hist:
        _add(
            findings,
            "history_group_readable",
            1,
            {"paths": _join_paths(group_hist)},
        )

    secret_files = [item for item in (env.get("secret_files") or []) if item.get("present")]
    world_secrets = [item for item in secret_files if _world(item)]
    group_secrets = [
        item
        for item in secret_files
        if item.get("group_readable") and item not in world_secrets
    ]
    if world_secrets:
        _add(
            findings,
            "secret_file_exposed",
            len(world_secrets),
            {"paths": _join_paths(world_secrets), "count": len(world_secrets)},
        )
    elif group_secrets:
        _add(
            findings,
            "secret_file_group",
            len(group_secrets),
            {"paths": _join_paths(group_secrets), "count": len(group_secrets)},
        )

    writable = [
        item
        for item in (env.get("configs") or [])
        if item.get("present") and item.get("world_writable")
    ]
    if writable:
        _add(
            findings,
            "config_world_writable",
            len(writable),
            {"paths": _join_paths(writable), "count": len(writable)},
        )

    termux = bool(os_info.get("termux") or firewall.get("termux"))
    active = firewall.get("active", None)
    if not termux:
        if active is False:
            _add(
                findings,
                "firewall_off",
                1,
                {"tool": firewall.get("tool") or "firewall"},
            )
        elif active is None:
            _add(findings, "firewall_unknown", 1, {})

    if os_info.get("is_root") is True:
        _add(findings, "running_as_root", 1, {})

    weak = []
    for item in browser.get("browsers") or []:
        if item.get("installed") and item.get("privacy") is False and item.get("name"):
            weak.append(str(item["name"]))
    if weak:
        _add(
            findings,
            "browser_no_privacy",
            len(weak),
            {"names": ", ".join(weak), "count": len(weak)},
        )
    return findings


def machine_ghost_id(signals: Sequence[Tuple[str, str]]) -> Tuple[str, List[str]]:
    """SHA-256 of stable local signals. Raw signal values are not returned."""
    clean: List[Tuple[str, str]] = []
    for name, value in signals:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        clean.append((str(name), text))
    if not clean:
        clean = [("fallback", "ghostleak")]
    payload = "\n".join(f"{name}\n{value}" for name, value in clean)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest, [name for name, _ in clean]


_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')


def collect_ghost_signals(run=None, read=None, environ=None) -> List[Tuple[str, str]]:
    """Gather stable hardware/OS signals. Hostnames, users, and IPs are excluded."""
    # Imported lazily so score stays easy to unit test without pulling safe
    # until a real collection is requested.
    from ghostleak import safe

    run = run or safe.run_cmd
    read = read or safe.read_text
    signals: List[Tuple[str, str]] = []
    try:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            text = read(path, limit=128)
            if text and text.strip():
                signals.append(("machine-id", text.strip().splitlines()[0].strip()))
                break
    except Exception:
        pass
    try:
        system = platform.system()
    except Exception:
        system = ""
    try:
        if system.lower() == "darwin":
            code, out, _err = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
            if code == 0 and out:
                match = _UUID.search(out)
                if match:
                    signals.append(("platform-uuid", match.group(1).strip()))
    except Exception:
        pass
    try:
        if safe.is_android(environ):
            for prop in ("ro.serialno", "ro.boot.serialno"):
                code, out, _err = run(["getprop", prop])
                if code == 0:
                    serial = (out or "").strip()
                    if serial and serial.lower() not in {"unknown", "android"}:
                        signals.append(("android-serial", serial))
                        break
    except Exception:
        pass
    try:
        cpuinfo = read("/proc/cpuinfo", limit=8192) or ""
        model = ""
        for line in cpuinfo.splitlines():
            lowered = line.lower()
            if lowered.startswith("model name") or lowered.startswith("hardware"):
                model = line.split(":", 1)[-1].strip()
                break
        if model:
            signals.append(("cpu-model", model))
    except Exception:
        pass
    try:
        if system:
            signals.append(("system", system))
        arch = platform.machine()
        if arch:
            signals.append(("arch", arch))
    except Exception:
        pass
    return signals


def family_of(os_info: Optional[dict]) -> str:
    info = os_info or {}
    if info.get("termux"):
        return "termux"
    system = str(info.get("system") or "").lower()
    if system == "darwin":
        return "darwin"
    if system == "linux":
        return "linux"
    return "other"
