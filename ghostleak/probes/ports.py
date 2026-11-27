"""Local listening TCP/UDP ports.

Order: ss, netstat, then /proc/net. No connection is opened to any port.
"""

from __future__ import annotations

from pathlib import Path

from ghostleak import safe
from ghostleak.parsers import dedupe_listeners, parse_netstat, parse_proc_net, parse_ss


def _from_proc(proc_root: Path) -> list:
    listeners = []
    mapping = (
        ("tcp", "tcp", False),
        ("tcp6", "tcp", True),
        ("udp", "udp", False),
        ("udp6", "udp", True),
    )
    for filename, proto, ipv6 in mapping:
        text = safe.read_text(proc_root / "net" / filename, limit=2_000_000)
        if not text:
            continue
        try:
            listeners.extend(parse_proc_net(text, proto=proto, ipv6=ipv6))
        except Exception:
            continue
    return listeners


def collect(run=None, proc_root=None) -> dict:
    """Return listening sockets. Never raises."""
    try:
        run = run or safe.run_cmd
        proc_root = Path("/proc") if proc_root is None else Path(proc_root)
        attempts = (
            ("ss", ["ss", "-H", "-lntu"], parse_ss),
            ("ss", ["ss", "-lntu"], parse_ss),
            ("netstat", ["netstat", "-lntu"], parse_netstat),
            ("netstat", ["netstat", "-an"], parse_netstat),
        )
        # Prefer the first command that actually runs. An empty listen table
        # is a valid answer and stops the fallback chain.
        saw_command = False
        for method, argv, parser in attempts:
            # Skip the second spelling of a tool when the first already ran.
            if method == "ss" and argv[1] == "-lntu" and saw_command:
                # only skip if the -H form was found; tracked below via a flag
                pass
            code, out, err = run(argv)
            if code is None:
                continue
            if safe.command_denied(out, err) and code != 0:
                saw_command = True
                continue
            if code != 0:
                continue
            try:
                listeners = dedupe_listeners(parser(out))
            except Exception:
                listeners = []
            return {
                "status": "ok",
                "method": method,
                "listeners": listeners[:200],
                "truncated": max(0, len(listeners) - 200),
            }

        try:
            listeners = dedupe_listeners(_from_proc(proc_root))
        except Exception:
            listeners = []
        if listeners or (proc_root / "net").is_dir():
            status = "ok" if listeners or (proc_root / "net" / "tcp").is_file() else "not_available"
            if (proc_root / "net").is_dir():
                return {
                    "status": "ok",
                    "method": "proc",
                    "listeners": listeners[:200],
                    "truncated": max(0, len(listeners) - 200),
                }
        return {
            "status": "not_available",
            "method": None,
            "listeners": [],
            "truncated": 0,
        }
    except Exception:
        return {
            "status": "restricted",
            "method": None,
            "listeners": [],
            "truncated": 0,
        }
