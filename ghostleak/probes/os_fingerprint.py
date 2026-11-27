"""OS and device fingerprint. Local files and allow-listed commands only."""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path

from ghostleak import safe
from ghostleak.parsers import parse_os_release


def _hostname() -> str:
    try:
        return os.uname().nodename
    except Exception:
        return ""


def _timezone() -> str:
    try:
        text = safe.read_text("/etc/timezone", limit=256)
        if text and text.strip():
            return text.strip().splitlines()[0].strip()
    except Exception:
        pass
    try:
        link = Path("/etc/localtime")
        if link.is_symlink():
            target = str(link.readlink())
            marker = "zoneinfo/"
            if marker in target:
                return target.split(marker, 1)[1]
    except OSError:
        pass
    try:
        names = [name for name in time.tzname if name]
        if names:
            return ",".join(names)
    except Exception:
        pass
    return ""


def _locale(environ) -> str:
    for key in ("LC_ALL", "LC_TIME", "LANG"):
        try:
            value = environ.get(key)
        except Exception:
            value = None
        if value:
            return str(value)
    return "C"


def _cpu_model(run) -> str:
    try:
        text = safe.read_text("/proc/cpuinfo", limit=8192) or ""
        for line in text.splitlines():
            lowered = line.lower()
            if lowered.startswith("model name") or lowered.startswith("hardware"):
                return line.split(":", 1)[-1].strip()
    except Exception:
        pass
    try:
        if platform.system().lower() == "darwin":
            code, out, _err = run(["sysctl", "-n", "machdep.cpu.brand_string"])
            if code == 0 and out.strip():
                return out.strip()
    except Exception:
        pass
    return ""


def _getprop(run, key: str) -> str:
    for binary in ("getprop", "/system/bin/getprop"):
        try:
            code, out, _err = run([binary, key])
        except Exception:
            continue
        if code == 0 and out and out.strip():
            return out.strip()
    return ""


def _distro(run, termux: bool, android: bool):
    distro = ""
    distro_id = ""
    try:
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            parsed = parse_os_release(safe.read_text(path) or "")
            if parsed:
                distro = parsed.get("PRETTY_NAME") or parsed.get("NAME") or ""
                distro_id = (parsed.get("ID") or "").lower()
                break
    except Exception:
        pass
    try:
        if platform.system().lower() == "darwin":
            code, name, _err = run(["sw_vers", "-productName"])
            code2, ver, _err2 = run(["sw_vers", "-productVersion"])
            bits = []
            if code == 0 and name.strip():
                bits.append(name.strip())
            if code2 == 0 and ver.strip():
                bits.append(ver.strip())
            if bits:
                distro = " ".join(bits)
                distro_id = "macos"
    except Exception:
        pass
    if termux or android:
        release = _getprop(run, "ro.build.version.release")
        model = _getprop(run, "ro.product.model")
        if release or model:
            label = "Android"
            if release:
                label = f"Android {release}"
            if model:
                label = f"{label} ({model})"
            return label, "android", model
        if not distro:
            return "Android", "android", ""
    return distro, distro_id, ""


def _is_root():
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except Exception:
        return None
    return None


def collect(environ=None, run=None) -> dict:
    """Return an OS fingerprint dict. Never raises."""
    try:
        env = os.environ if environ is None else environ
        run = run or safe.run_cmd
        system = ""
        kernel = ""
        arch = ""
        try:
            system = platform.system() or ""
            kernel = platform.release() or ""
            arch = platform.machine() or ""
        except Exception:
            pass
        termux = safe.is_termux(env if environ is not None else None)
        # When the caller passes an explicit env, honour only that env for
        # Termux detection. When environ is None, safe.is_termux checks files.
        if environ is None:
            termux = safe.is_termux(None)
        android = termux or safe.is_android(env if environ is not None else None)
        if environ is None:
            android = termux or safe.is_android(None)
        distro, distro_id, model = _distro(run, termux, android)
        cores = None
        try:
            cores = os.cpu_count()
        except Exception:
            cores = None
        if termux:
            family = "termux"
        elif system.lower() == "darwin":
            family = "darwin"
        elif system.lower() == "linux":
            family = "linux"
        else:
            family = "other"
        return {
            "status": "ok",
            "system": system or None,
            "distro": distro or None,
            "distro_id": distro_id or None,
            "kernel": kernel or None,
            "arch": arch or None,
            "cpu_cores": cores,
            "cpu_model": _cpu_model(run) or None,
            "hostname": _hostname() or None,
            "termux": bool(termux),
            "android": bool(android),
            "device_model": model or None,
            "timezone": _timezone() or None,
            "locale": _locale(env) or None,
            "python": sys.version.split()[0],
            "is_root": _is_root(),
            "family": family,
        }
    except Exception:
        return {"status": "restricted", "termux": False, "is_root": None, "family": "other"}
