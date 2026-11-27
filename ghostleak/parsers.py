"""Pure parsers for local command and /proc output. No I/O."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def decode_le_ipv4(hexaddr: str) -> Optional[str]:
    """Decode a little-endian IPv4 hex word from /proc/net."""
    try:
        raw = bytes.fromhex(hexaddr)
    except (ValueError, TypeError):
        return None
    if len(raw) != 4:
        return None
    ordered = raw[::-1]
    return ".".join(str(byte) for byte in ordered)


def _compress_ipv6(hextets: List[str]) -> str:
    best = None
    index = 0
    while index < 8:
        if hextets[index] == "0":
            end = index
            while end < 8 and hextets[end] == "0":
                end += 1
            if end - index > 1 and (best is None or (end - index) > (best[1] - best[0])):
                best = (index, end)
            index = end
        else:
            index += 1
    if best is None:
        return ":".join(hextets)
    left = ":".join(hextets[: best[0]])
    right = ":".join(hextets[best[1] :])
    if not left and not right:
        return "::"
    return f"{left}::{right}"


def decode_le_ipv6(hexaddr: str) -> Optional[str]:
    """Decode a /proc/net/tcp6 local address (4 little-endian 32-bit words)."""
    try:
        raw = bytes.fromhex(hexaddr)
    except (ValueError, TypeError):
        return None
    if len(raw) != 16:
        return None
    ordered = bytearray()
    for index in range(0, 16, 4):
        ordered.extend(raw[index : index + 4][::-1])
    if ordered == b"\x00" * 16:
        return "::"
    hextets = []
    for index in range(0, 16, 2):
        number = (ordered[index] << 8) | ordered[index + 1]
        hextets.append(f"{number:x}")
    return _compress_ipv6(hextets)


def format_endpoint(addr, port) -> str:
    """Render host:port. IPv6 hosts are bracketed so ``::`` is not ``:::port``."""
    host = "" if addr is None else str(addr).strip()
    if host.startswith("[") and host.endswith("]"):
        return f"{host}:{port}"
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def classify_addr(addr: str) -> str:
    """Return wildcard, loopback, or address."""
    if addr is None:
        return "wildcard"
    host = str(addr).strip().strip("[]").lower()
    if host in {"", "*", "0.0.0.0", "::", "[::]"}:
        return "wildcard"
    if host == "::1" or host == "localhost" or host.startswith("127."):
        return "loopback"
    return "address"


def is_routable(addr: str) -> bool:
    """True for an address that is not loopback or link-local."""
    if not addr:
        return False
    host = str(addr).split("%", 1)[0].strip().strip("[]")
    if not host:
        return False
    if ":" in host:
        low = host.lower()
        if low in {"::", "::1"} or low.startswith("fe80:"):
            return False
        return True
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    if any(num < 0 or num > 255 for num in nums):
        return False
    if nums[0] in {0, 127}:
        return False
    if nums[0] == 169 and nums[1] == 254:
        return False
    return True


_VPN_NAME = re.compile(
    r"^(tun\d*|tap\d*|wg\d*|utun\d*|tailscale\d*|ppp\d*|ipsec\d*|"
    r"wireguard\d*|nordlynx\d*|proton\d*|mullvad\d*|zt\d*|awg\d*|tunnel\d*)$",
    re.I,
)


def is_vpn_iface(name: str) -> bool:
    if not name:
        return False
    return _VPN_NAME.match(str(name).strip()) is not None


def _parse_port(text: str) -> Optional[int]:
    try:
        port = int(str(text), 10)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def split_endpoint(token: str):
    """Split ``host:port`` or ``[host]:port``. Port ``*`` returns None."""
    if not token or not isinstance(token, str):
        return None, None
    text = token.strip()
    if not text or text == "*":
        return None, None
    host = None
    port_text = None
    if text.startswith("[") and "]" in text:
        host = text[1 : text.index("]")]
        rest = text[text.index("]") + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
        else:
            return None, None
    elif text.count(":") >= 2:
        host, port_text = text.rsplit(":", 1)
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        return None, None
    if port_text in {"", "*"}:
        return None, None
    port = _parse_port(port_text)
    if port is None or host is None:
        return None, None
    return host.strip(), port


def _listener(proto: str, host: str, port: int) -> dict:
    addr = host.strip().strip("[]")
    if addr == "":
        addr = "*"
    return {
        "proto": "udp" if proto == "udp" else "tcp",
        "addr": addr,
        "port": port,
        "scope": classify_addr(addr),
    }


def parse_proc_net(text: str, proto: str = "tcp", ipv6: bool = False) -> List[dict]:
    listeners = []
    if not text:
        return listeners
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith("sl ") or lowered.startswith("sl\t"):
            continue
        parts = stripped.split()
        if len(parts) < 4 or ":" not in parts[1]:
            continue
        state = parts[3].upper()
        # TCP LISTEN is 0A. UDP rows are bound sockets; keep them.
        if proto == "tcp" and state != "0A":
            continue
        ip_hex, port_hex = parts[1].split(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        if not 0 <= port <= 65535:
            continue
        addr = decode_le_ipv6(ip_hex) if ipv6 else decode_le_ipv4(ip_hex)
        if not addr:
            continue
        listeners.append(_listener(proto, addr, port))
    return listeners


def parse_proc_route(text: str) -> Optional[str]:
    """Default gateway from /proc/net/route, or None."""
    if not text:
        return None
    lines = text.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[1] != "00000000":
            continue
        gateway = decode_le_ipv4(parts[2])
        if gateway and gateway != "0.0.0.0":
            return gateway
    return None


def parse_ss(text: str) -> List[dict]:
    listeners = []
    if not text:
        return listeners
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        head = parts[0].lower()
        if head in {"netid", "state"}:
            continue
        proto = None
        if head in {"tcp", "tcp4", "tcp6"}:
            proto = "tcp"
        elif head in {"udp", "udp4", "udp6"}:
            proto = "udp"
        else:
            continue
        if proto == "tcp" and not any(part.upper() == "LISTEN" for part in parts):
            continue
        if proto == "udp" and any(part.upper() == "ESTAB" for part in parts):
            continue
        chosen = None
        for token in parts:
            host, port = split_endpoint(token)
            if host is None or port is None:
                continue
            chosen = (host, port)
            break
        if chosen is None:
            continue
        listeners.append(_listener(proto, chosen[0], chosen[1]))
    return listeners


def parse_netstat(text: str) -> List[dict]:
    listeners = []
    if not text:
        return listeners
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        head = parts[0].lower()
        if head in {"tcp", "tcp4", "tcp6"}:
            proto = "tcp"
            if parts[-1].upper() != "LISTEN":
                continue
        elif head in {"udp", "udp4", "udp6"}:
            proto = "udp"
        else:
            continue
        host, port = split_endpoint(parts[3])
        if host is None or port is None:
            continue
        listeners.append(_listener(proto, host, port))
    return listeners


_IP_ADDR = re.compile(r"^\d+:\s+(\S+)\s+inet6?\s+(\S+)")


def parse_ip_addr(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    if not text:
        return found
    for line in text.splitlines():
        match = _IP_ADDR.match(line.strip())
        if not match:
            continue
        name = match.group(1)
        addr = match.group(2).split("/", 1)[0].split("%", 1)[0]
        bucket = found.setdefault(name, [])
        if addr not in bucket:
            bucket.append(addr)
    return found


def parse_ifconfig(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    if not text:
        return found
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split()[0].rstrip(":")
            if name:
                current = name
                found.setdefault(current, [])
            continue
        if current is None:
            continue
        match = re.search(r"\binet6?\s+(?:addr:)?(\S+)", line)
        if not match:
            continue
        addr = match.group(1).split("%", 1)[0]
        if addr.lower() in {"addr", "inet"}:
            continue
        if addr not in found[current]:
            found[current].append(addr)
    return found


def parse_resolv(text: str) -> List[str]:
    servers = []
    if not text:
        return servers
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0].lower() == "nameserver":
            if parts[1] not in servers:
                servers.append(parts[1])
    return servers


def parse_scutil_dns(text: str) -> List[str]:
    servers = []
    if not text:
        return servers
    for line in text.splitlines():
        match = re.search(r"nameserver(?:\[\d+\])?\s*:\s*(\S+)", line, re.I)
        if match and match.group(1) not in servers:
            servers.append(match.group(1))
    return servers


def parse_gateway_text(text: str) -> Optional[str]:
    """Gateway from `ip route`, `route -n`, or `route -n get default`."""
    if not text:
        return None
    for line in text.splitlines():
        match = re.search(r"\bgateway:\s+(\S+)", line, re.I)
        if match:
            return match.group(1)
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "default" and "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts):
                return parts[index + 1]
        if parts[0] == "0.0.0.0" and len(parts) >= 2 and _IPV4_RE.match(parts[1]):
            return parts[1]
    return None


def parse_os_release(text: str) -> dict:
    data = {}
    if not text:
        return data
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def parse_ufw(text: str) -> Optional[bool]:
    if not text:
        return None
    low = text.lower()
    if "status: active" in low:
        return True
    if "status: inactive" in low:
        return False
    return None


def parse_iptables(text: str) -> Optional[bool]:
    """True when a DROP/REJECT policy or a non-ACCEPT rule is present."""
    if not text or not text.strip():
        return None
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    if not lines:
        return None
    blob = "\n".join(lines).lower()
    if "permission denied" in blob or "operation not permitted" in blob:
        return None
    has_policy = False
    for line in lines:
        if line.startswith("-P "):
            has_policy = True
            target = line.split()[-1].upper() if line.split() else ""
            if target in {"DROP", "REJECT"}:
                return True
        if line.startswith("-A ") or line.startswith("-I ") or line.startswith("-R "):
            target = line.split()[-1].upper() if line.split() else ""
            upper = line.upper()
            if target not in {"ACCEPT"} or " DROP" in upper or " REJECT" in upper:
                if target in {"DROP", "REJECT"} or "DROP" in upper or "REJECT" in upper:
                    return True
    if has_policy:
        return False
    return None


def parse_nft(text: str) -> Optional[bool]:
    if text is None:
        return None
    body = text.strip()
    if not body:
        return False
    low = body.lower()
    if "permission denied" in low or "operation not permitted" in low:
        return None
    if "drop" in low or "reject" in low:
        return True
    if "hook" in low or "chain" in low:
        return False
    return None


def parse_alf(text: str) -> Optional[bool]:
    if text is None:
        return None
    low = text.strip().lower()
    if not low:
        return None
    if low in {"1", "on", "true"}:
        return True
    if low in {"0", "off", "false"}:
        return False
    if "enabled" in low or "state = 1" in low:
        return True
    if "disabled" in low or "state = 0" in low:
        return False
    return None


def parse_pf(text: str) -> Optional[bool]:
    if not text:
        return None
    low = text.lower()
    if "status: enabled" in low or "status: active" in low:
        return True
    if "status: disabled" in low:
        return False
    return None


def dedupe_listeners(listeners: List[dict]) -> List[dict]:
    seen = set()
    ordered = []
    for item in listeners:
        try:
            key = (item.get("proto"), item.get("addr"), int(item.get("port")))
        except (TypeError, ValueError):
            continue
        if key in seen:
            continue
        seen.add(key)
        ordered.append(
            {
                "proto": item.get("proto") or "tcp",
                "addr": item.get("addr") or "*",
                "port": key[2],
                "scope": item.get("scope") or classify_addr(item.get("addr") or ""),
            }
        )
    ordered.sort(key=lambda row: (row["proto"], row["port"], row["addr"]))
    return ordered
