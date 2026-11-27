"""Host firewall indicators and root posture. No rules are changed."""

from __future__ import annotations

import os

from ghostleak import safe
from ghostleak.parsers import parse_alf, parse_iptables, parse_nft, parse_pf, parse_ufw


def _is_root():
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except Exception:
        return None
    return None


def _finish(active, tool, status, termux: bool) -> dict:
    if active is True:
        detail = "active"
    elif active is False:
        detail = "inactive"
    elif termux:
        detail = "termux"
    else:
        detail = "unknown"
    return {
        "status": status,
        "active": active,
        "tool": tool,
        "detail": detail,
        "termux": termux,
        "is_root": _is_root(),
    }


def collect(environ=None, run=None) -> dict:
    """Return firewall posture. Never raises. Never invokes sudo."""
    try:
        env = os.environ if environ is None else environ
        run = run or safe.run_cmd
        termux = safe.is_termux(env if environ is not None else None)
        if environ is None:
            termux = safe.is_termux(None)
        if termux:
            return _finish(None, None, "not_available", True)

        try:
            system = __import__("platform").system().lower()
        except Exception:
            system = ""

        if system == "darwin":
            checks = (
                ("alf", ["socketfilterfw", "--getglobalstate"], parse_alf),
                (
                    "alf",
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                    parse_alf,
                ),
                (
                    "alf",
                    ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                    parse_alf,
                ),
                ("pf", ["pfctl", "-s", "info"], parse_pf),
            )
        else:
            checks = (
                ("ufw", ["ufw", "status"], parse_ufw),
                ("nft", ["nft", "list", "ruleset"], parse_nft),
                ("iptables", ["iptables", "-S"], parse_iptables),
                ("iptables", ["ip6tables", "-S"], parse_iptables),
            )

        any_denied = False
        any_found = False
        for tool, argv, parser in checks:
            code, out, err = run(argv)
            if code is None:
                continue
            any_found = True
            if safe.command_denied(out, err):
                any_denied = True
                continue
            try:
                parsed = parser(out)
            except Exception:
                parsed = None
            if parsed is None and code != 0:
                continue
            if parsed is not None:
                return _finish(parsed, tool, "ok", False)

        if any_denied:
            return _finish(None, None, "restricted", False)
        if not any_found:
            return _finish(None, None, "not_available", False)
        return _finish(None, None, "ok", False)
    except Exception:
        return {
            "status": "restricted",
            "active": None,
            "tool": None,
            "detail": "unknown",
            "termux": False,
            "is_root": None,
        }
