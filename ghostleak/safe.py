"""Safe local I/O helpers.

Every OS probe goes through this module. Commands are allow-listed, timed out,
and swallowed on failure so an unprivileged Termux or locked-down Linux session
cannot crash the scan. Network clients are not allow-listed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional, Sequence, Tuple

# Basename allow-list. Anything else, including curl/wget/ssh, is refused
# before subprocess is invoked.
ALLOWED_COMMANDS = frozenset(
    {
        "ip",
        "ifconfig",
        "ss",
        "netstat",
        "ufw",
        "iptables",
        "ip6tables",
        "nft",
        "pfctl",
        "scutil",
        "route",
        "getprop",
        "socketfilterfw",
        "defaults",
        "sysctl",
        "sw_vers",
        "ioreg",
    }
)

CmdResult = Tuple[Optional[int], str, str]


def run_cmd(argv: Sequence[str], timeout: float = 3.0) -> CmdResult:
    """Run one local command. Returns (returncode, stdout, stderr).

    returncode is None when the command is missing, blocked, or times out.
    This function does not raise.
    """
    try:
        if not argv or isinstance(argv, (str, bytes)):
            return None, "", ""
        base = os.path.basename(str(argv[0]))
        if base not in ALLOWED_COMMANDS:
            return None, "", ""
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return None, "", ""


def read_text(path, limit: int = 65536) -> Optional[str]:
    """Read up to `limit` characters of a local text file, or None."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def command_denied(stdout: str, stderr: str) -> bool:
    blob = f"{stdout}\n{stderr}".lower()
    markers = (
        "permission denied",
        "operation not permitted",
        "must be root",
        "superuser",
        "not permitted",
    )
    return any(marker in blob for marker in markers)


def is_termux(environ=None) -> bool:
    """True when the process looks like Termux (userland Android)."""
    env = os.environ if environ is None else environ
    try:
        if env.get("TERMUX_VERSION") or env.get("TERMUX_API_VERSION"):
            return True
        prefix = str(env.get("PREFIX") or "")
        if "com.termux" in prefix:
            return True
    except Exception:
        pass
    # Fall back to the filesystem only when the caller did not hand us an
    # explicit environment. Tests pass a dict and must not inherit the host.
    if environ is not None:
        return False
    try:
        return Path("/data/data/com.termux/files/usr/bin").is_dir()
    except OSError:
        return False


def is_android(environ=None) -> bool:
    if is_termux(environ):
        return True
    env = os.environ if environ is None else environ
    try:
        root = str(env.get("ANDROID_ROOT") or "")
        if root.startswith("/system"):
            return True
    except Exception:
        pass
    if environ is not None:
        return False
    try:
        return Path("/system/build.prop").is_file()
    except OSError:
        return False


def guard_probe(fn):
    """Run a probe and always return a dict."""
    try:
        data = fn()
    except Exception:
        return {"status": "restricted", "error": "probe-failed"}
    if not isinstance(data, dict):
        return {"status": "restricted", "error": "probe-failed"}
    data.setdefault("status", "ok")
    return data
