"""Read-only browser presence and privacy-profile signals.

This probe checks whether a browser exists and whether a known privacy marker
is present (Firefox user.js, or a known content-blocker extension directory).
It does not open cookies, history, password stores, or session files.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ghostleak import safe

_CHROME_PRIVACY_IDS = (
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
    "ddkjiahejlhfcafbddmgiahcphecmpfh",  # uBlock Origin Lite
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",  # Privacy Badger
    "bkdgflcldnnnapblkhphbgpggdiikppg",  # DuckDuckGo Privacy Essentials
)

_FIREFOX_MARKERS = (
    "uBlock0@raymondhill.net",
    "{73a6fe31-595d-460b-a920-fcc0f8843232}",  # NoScript
)

_BROWSERS = (
    {
        "name": "firefox",
        "bins": ("firefox", "firefox-esr"),
        "apps": ("Firefox.app",),
        "roots": (
            ".mozilla/firefox",
            "Library/Application Support/Firefox",
            ".var/app/org.mozilla.firefox/.mozilla/firefox",
        ),
        "kind": "firefox",
    },
    {
        "name": "librewolf",
        "bins": ("librewolf",),
        "apps": ("LibreWolf.app",),
        "roots": (".librewolf",),
        "kind": "private",
    },
    {
        "name": "tor-browser",
        "bins": ("tor-browser", "torbrowser-launcher"),
        "apps": ("Tor Browser.app",),
        "roots": ("tor-browser", ".local/share/torbrowser"),
        "kind": "private",
    },
    {
        "name": "chromium",
        "bins": ("chromium", "chromium-browser"),
        "apps": ("Chromium.app",),
        "roots": (".config/chromium",),
        "kind": "chromium",
    },
    {
        "name": "chrome",
        "bins": ("google-chrome", "google-chrome-stable"),
        "apps": ("Google Chrome.app",),
        "roots": (
            ".config/google-chrome",
            "Library/Application Support/Google/Chrome",
        ),
        "kind": "chromium",
    },
    {
        "name": "brave",
        "bins": ("brave", "brave-browser"),
        "apps": ("Brave Browser.app",),
        "roots": (".config/BraveSoftware/Brave-Browser",),
        "kind": "chromium",
    },
    {
        "name": "edge",
        "bins": ("microsoft-edge", "microsoft-edge-stable"),
        "apps": ("Microsoft Edge.app",),
        "roots": (".config/microsoft-edge",),
        "kind": "chromium",
    },
    {
        "name": "vivaldi",
        "bins": ("vivaldi", "vivaldi-stable"),
        "apps": ("Vivaldi.app",),
        "roots": (".config/vivaldi",),
        "kind": "chromium",
    },
    {
        "name": "safari",
        "bins": (),
        "apps": ("Safari.app",),
        "roots": (),
        "kind": "safari",
    },
)


def _which(name: str) -> bool:
    try:
        return bool(shutil.which(name))
    except OSError:
        return False


def _app_installed(home: Path, apps) -> bool:
    roots = [Path("/Applications")]
    try:
        roots.append(home / "Applications")
    except Exception:
        pass
    for root in roots:
        for app in apps:
            try:
                if (root / app).exists():
                    return True
            except OSError:
                continue
    return False


def _firefox_profiles(root: Path):
    profiles = []
    text = safe.read_text(root / "profiles.ini", limit=32768)
    if text:
        relative = None
        path_value = None

        def flush():
            nonlocal relative, path_value
            if path_value and "\x00" not in path_value:
                if relative == "0":
                    profiles.append(Path(path_value))
                else:
                    profiles.append(root / path_value)
            relative = None
            path_value = None

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                flush()
                continue
            if stripped.startswith("IsRelative="):
                relative = stripped.split("=", 1)[1].strip()
            elif stripped.startswith("Path="):
                path_value = stripped.split("=", 1)[1].strip()
        flush()
    if profiles:
        return profiles
    try:
        for child in root.iterdir():
            if not child.is_dir() or child.name in {"Crash Reports", "Pending Pings"}:
                continue
            try:
                if (
                    (child / "extensions").is_dir()
                    or (child / "user.js").is_file()
                    or (child / "prefs.js").is_file()
                ):
                    profiles.append(child)
            except OSError:
                continue
    except OSError:
        return []
    return profiles


def _firefox_privacy(root: Path):
    if not root.exists():
        return None
    profiles = _firefox_profiles(root)
    if not profiles:
        return None
    for profile in profiles:
        try:
            if (profile / "user.js").is_file():
                return True
            extensions = profile / "extensions"
            for marker in _FIREFOX_MARKERS:
                if (extensions / f"{marker}.xpi").is_file() or (extensions / marker).exists():
                    return True
        except OSError:
            continue
    return False


def _chromium_privacy(root: Path):
    if not root.exists():
        return None
    try:
        profiles = [
            child
            for child in root.iterdir()
            if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile"))
        ]
    except OSError:
        return None
    if not profiles:
        return None
    for profile in profiles:
        for extension_id in _CHROME_PRIVACY_IDS:
            try:
                if (profile / "Extensions" / extension_id).is_dir():
                    return True
            except OSError:
                continue
    return False


def _combine(values):
    if any(value is True for value in values):
        return True
    if any(value is False for value in values):
        return False
    return None


def _note(kind: str, privacy):
    if kind == "private":
        return "privacy-browser"
    if kind == "safari":
        return "not-inspected"
    if privacy is True:
        return "privacy-signal"
    if privacy is False:
        return "no-privacy-signal"
    return "unknown"


def collect(home=None, system=None) -> dict:
    """Detect browsers and privacy markers. Never raises."""
    try:
        if home is None:
            try:
                home_path = Path.home()
            except Exception:
                home_path = None
        else:
            home_path = Path(home)
        if home_path is None:
            return {"status": "restricted", "browsers": []}
        if system is None:
            try:
                system = __import__("platform").system()
            except Exception:
                system = ""
        found = []
        for spec in _BROWSERS:
            binary = any(_which(name) for name in spec["bins"])
            app = False
            if str(system).lower() == "darwin" or spec["kind"] == "safari":
                app = _app_installed(home_path, spec["apps"])
            roots = []
            for relative in spec["roots"]:
                candidate = home_path / relative
                try:
                    if candidate.exists():
                        roots.append(candidate)
                except OSError:
                    continue
            if not binary and not app and not roots:
                continue
            if spec["kind"] == "private":
                privacy = True
            elif spec["kind"] == "safari":
                privacy = None
            elif spec["kind"] == "firefox":
                privacy = _combine([_firefox_privacy(root) for root in roots]) if roots else None
            elif spec["kind"] == "chromium":
                privacy = _combine([_chromium_privacy(root) for root in roots]) if roots else None
            else:
                privacy = None
            found.append(
                {
                    "name": spec["name"],
                    "installed": True,
                    "privacy": privacy,
                    "note": _note(spec["kind"], privacy),
                }
            )
        found.sort(key=lambda item: item["name"])
        return {"status": "ok", "browsers": found}
    except Exception:
        return {"status": "restricted", "browsers": []}
