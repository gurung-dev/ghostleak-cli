"""Shared helpers for GhostLeak tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostleak.redact import classify_name, is_proxy_name  # noqa: E402


def assert_absent(haystack: str, needles, label: str = "output") -> None:
    for needle in needles:
        if needle and len(needle) >= 8 and needle in haystack:
            raise AssertionError(
                f"{label} contained a forbidden string of length {len(needle)}"
            )


def assert_no_secret_values(haystack: str, environ=None, label: str = "output") -> None:
    env = os.environ if environ is None else environ
    for name, value in list(env.items()):
        if not isinstance(value, str) or len(value) < 8:
            continue
        if classify_name(str(name))[0] or is_proxy_name(str(name)):
            if value in haystack:
                raise AssertionError(
                    f"{label} leaked the value of {name} (len={len(value)})"
                )


def empty_sections():
    return {
        "os": {
            "status": "ok",
            "system": "Linux",
            "distro_id": "ubuntu",
            "termux": False,
            "is_root": False,
            "hostname": "secret-host",
        },
        "network": {
            "status": "ok",
            "interfaces": [{"name": "lo", "addresses": ["127.0.0.1"]}],
            "vpn_interfaces": [],
            "dns": [],
            "gateway": None,
            "proxy_vars": [],
        },
        "ports": {"status": "ok", "listeners": [], "method": "test"},
        "env": {
            "status": "ok",
            "sensitive": [],
            "ssh": {"present": False, "keys": []},
            "histories": [],
            "secret_files": [],
            "configs": [],
        },
        "firewall": {"status": "ok", "active": True, "tool": "ufw", "termux": False},
        "browser": {
            "status": "ok",
            "browsers": [{"name": "firefox", "installed": True, "privacy": True}],
        },
    }
