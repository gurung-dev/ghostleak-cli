"""Environment names and permission bits for SSH, history, and credential files.

File contents are never read. History, private keys, and credential files are
stat'd only. Sensitive environment values are not copied into the result.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ghostleak.redact import sensitive_names

_HISTORY = (
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".local/share/fish/fish_history",
    ".python_history",
)

_CONFIGS = (
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".zprofile",
    ".config/fish/config.fish",
)

_SECRET_FILES = (
    ".netrc",
    ".pgpass",
    ".aws/credentials",
    ".aws/config",
    ".config/gh/hosts.yml",
    ".npmrc",
    ".docker/config.json",
    ".git-credentials",
    ".config/hub",
)


def display_path(path: Path, home: Path) -> str:
    """Show a path under home as ``~/...`` so the username stays out of reports."""
    try:
        path_s = str(path)
        home_s = str(home)
        if path_s == home_s:
            return "~"
        prefix = home_s + os.sep
        if path_s.startswith(prefix):
            return "~" + path_s[len(home_s) :]
    except Exception:
        pass
    return str(path)


def describe_path(path: Path, home: Path) -> dict:
    shown = display_path(path, home)
    try:
        st = path.stat()
    except OSError:
        present = False
        try:
            present = path.exists()
        except OSError:
            present = False
        return {"path": shown, "present": present, "restricted": not present}
    mode = stat.S_IMODE(st.st_mode)
    return {
        "path": shown,
        "present": True,
        "mode": f"{mode:04o}",
        "world_readable": bool(mode & 0o004),
        "world_writable": bool(mode & 0o002),
        "group_readable": bool(mode & 0o040),
        "is_dir": stat.S_ISDIR(st.st_mode),
    }


def _private_key_name(name: str) -> bool:
    if not name or name.endswith(".pub"):
        return False
    if name in {"known_hosts", "known_hosts.old", "authorized_keys", "config"}:
        return False
    if name.startswith("id_"):
        return True
    if name.endswith(".pem") or name.endswith("_key"):
        return True
    return False


def _ssh(home: Path) -> dict:
    directory = home / ".ssh"
    info = describe_path(directory, home)
    info["keys"] = []
    if not info.get("present") or not info.get("is_dir"):
        info["present"] = bool(info.get("present") and info.get("is_dir"))
        return info
    try:
        children = list(directory.iterdir())
    except OSError:
        info["restricted"] = True
        return info
    for child in children:
        try:
            name = child.name
        except Exception:
            continue
        if not _private_key_name(name):
            continue
        described = describe_path(child, home)
        if described.get("present") and not described.get("is_dir"):
            info["keys"].append(described)
    for extra in ("config", "authorized_keys"):
        described = describe_path(directory / extra, home)
        if described.get("present") and not described.get("is_dir"):
            info["keys"].append(described)
    known = describe_path(directory / "known_hosts", home)
    if known.get("present") and known.get("world_writable"):
        info["keys"].append(known)
    info["keys"].sort(key=lambda item: item.get("path") or "")
    return info


def _present_rows(home: Path, relatives) -> list:
    rows = []
    for relative in relatives:
        described = describe_path(home / relative, home)
        if described.get("present"):
            rows.append(described)
    return rows


def resolve_home(home=None):
    if home is not None:
        return Path(home)
    try:
        return Path.home()
    except Exception:
        return None


def collect(environ=None, home=None) -> dict:
    """Audit env names and file modes. Never raises. Never reads secret bytes."""
    try:
        env = os.environ if environ is None else environ
        home_path = resolve_home(home)
        result = {
            "status": "ok",
            "sensitive": sensitive_names(env),
            "ssh": {"present": False, "keys": []},
            "histories": [],
            "secret_files": [],
            "configs": [],
        }
        if home_path is None:
            result["status"] = "restricted"
            return result
        result["ssh"] = _ssh(home_path)
        result["histories"] = _present_rows(home_path, _HISTORY)
        result["secret_files"] = _present_rows(home_path, _SECRET_FILES)
        result["configs"] = _present_rows(home_path, _CONFIGS)
        return result
    except Exception:
        return {
            "status": "restricted",
            "sensitive": [],
            "ssh": {"present": False, "keys": []},
            "histories": [],
            "secret_files": [],
            "configs": [],
        }
