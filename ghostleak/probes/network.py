"""Local interfaces, gateway, DNS resolvers, VPN tunnels, and proxy env names.

Proxy values are never copied into the result. DNS servers are read from local
config only; names are not resolved.
"""

from __future__ import annotations

import os
from pathlib import Path

from ghostleak import safe
from ghostleak.parsers import (
    is_vpn_iface,
    parse_gateway_text,
    parse_ifconfig,
    parse_ip_addr,
    parse_proc_route,
    parse_resolv,
    parse_scutil_dns,
)
from ghostleak.redact import is_proxy_name


def _empty(status: str, method=None) -> dict:
    return {
        "status": status,
        "interfaces": [],
        "gateway": None,
        "dns": [],
        "vpn_interfaces": [],
        "proxy_vars": [],
        "method": method,
    }


def _proxy_names(environ) -> list:
    names = []
    try:
        keys = list(environ.keys())
    except Exception:
        return names
    for name in keys:
        try:
            if is_proxy_name(str(name)):
                names.append(str(name))
        except Exception:
            continue
    return sorted(set(names))


def _interfaces_from_map(addr_map: dict) -> list:
    interfaces = []
    for name in sorted(addr_map):
        addresses = []
        for addr in addr_map[name]:
            if addr and addr not in addresses:
                addresses.append(addr)
        interfaces.append({"name": name, "addresses": addresses})
    return interfaces


def _vpn_names(interfaces: list) -> list:
    names = []
    for iface in interfaces:
        name = iface.get("name") or ""
        if is_vpn_iface(name) and name not in names:
            names.append(name)
    return names


def _getprop_dns(run) -> list:
    servers = []
    for prop in ("net.dns1", "net.dns2", "net.dns3", "net.dns4"):
        code, out, _err = run(["getprop", prop])
        if code == 0:
            value = (out or "").strip()
            if value and value not in servers and value.lower() != "unknown":
                servers.append(value)
    return servers


def collect(
    environ=None,
    run=None,
    resolv_path=None,
    route_path=None,
    sysfs_net=None,
) -> dict:
    """Return network posture. Never raises."""
    try:
        env = os.environ if environ is None else environ
        run = run or safe.run_cmd
        resolv_path = Path("/etc/resolv.conf") if resolv_path is None else Path(resolv_path)
        route_path = Path("/proc/net/route") if route_path is None else Path(route_path)
        sysfs_net = Path("/sys/class/net") if sysfs_net is None else Path(sysfs_net)
        try:
            system = __import__("platform").system().lower()
        except Exception:
            system = ""

        addr_map = {}
        method = None
        code, out, _err = run(["ip", "-o", "addr"])
        if code == 0 and out.strip():
            addr_map = parse_ip_addr(out)
            method = "ip"
        if not addr_map:
            code, out, _err = run(["ifconfig", "-a"])
            if code == 0 and out.strip():
                addr_map = parse_ifconfig(out)
                method = "ifconfig"
            elif code is None:
                code, out, _err = run(["ifconfig"])
                if code == 0 and out.strip():
                    addr_map = parse_ifconfig(out)
                    method = "ifconfig"
        interfaces = _interfaces_from_map(addr_map)
        status = "ok" if interfaces and any(iface["addresses"] for iface in interfaces) else None

        if not interfaces:
            names = []
            try:
                if sysfs_net.is_dir():
                    names = sorted(
                        entry.name
                        for entry in sysfs_net.iterdir()
                        if entry.name and not entry.name.startswith(".")
                    )
            except OSError:
                names = []
            if names:
                interfaces = [{"name": name, "addresses": []} for name in names]
                method = method or "sysfs"
                status = "restricted"

        if status is None:
            status = "not_available"
            method = method or "none"

        gateway = None
        try:
            if system != "darwin":
                route_text = safe.read_text(route_path, limit=65536)
                if route_text:
                    gateway = parse_proc_route(route_text)
        except Exception:
            gateway = None
        if not gateway and system != "darwin":
            code, out, _err = run(["ip", "route", "show", "default"])
            if code == 0:
                gateway = parse_gateway_text(out)
        if not gateway and system != "darwin":
            code, out, _err = run(["route", "-n"])
            if code == 0:
                gateway = parse_gateway_text(out)
        if not gateway and system == "darwin":
            code, out, _err = run(["route", "-n", "get", "default"])
            if code == 0:
                gateway = parse_gateway_text(out)

        dns = []
        try:
            dns = parse_resolv(safe.read_text(resolv_path, limit=16384) or "")
        except Exception:
            dns = []
        android = safe.is_android(env if environ is not None else None)
        if environ is None:
            android = safe.is_android(None)
        if not dns and android:
            dns = _getprop_dns(run)
        if not dns and system == "darwin":
            code, out, _err = run(["scutil", "--dns"])
            if code == 0:
                dns = parse_scutil_dns(out)

        return {
            "status": status,
            "interfaces": interfaces,
            "gateway": gateway,
            "dns": dns,
            "vpn_interfaces": _vpn_names(interfaces),
            "proxy_vars": _proxy_names(env),
            "method": method,
        }
    except Exception:
        return _empty("restricted")
