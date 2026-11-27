"""Browser probe is read-only: cookie and password files stay unread."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ghostleak.probes import browser


class BrowserTests(unittest.TestCase):
    def test_cookie_stores_are_not_read_and_privacy_flags_work(self):
        cookie = "CANARY-COOKIE-SECRET-xyz"
        history = "CANARY-HISTORY-URL-xyz"
        password = "CANARY-BROWSER-PASSWORD"
        userjs = "CANARY-USERJS-SECRET"
        chrome_cookie = "CANARY-CHROME-COOKIE"
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            profile = home / ".mozilla" / "firefox" / "abc.default"
            profile.mkdir(parents=True)
            (home / ".mozilla" / "firefox" / "profiles.ini").write_text(
                "[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\n",
                encoding="utf-8",
            )
            (profile / "cookies.sqlite").write_text(cookie, encoding="utf-8")
            (profile / "places.sqlite").write_text(history, encoding="utf-8")
            (profile / "logins.json").write_text(
                '{"password":"%s"}' % password,
                encoding="utf-8",
            )
            (profile / "prefs.js").write_text("user_pref('secret', '%s');\n" % password, encoding="utf-8")
            data = browser.collect(home=home, system="Linux")
            blob = json.dumps(data)
            self.assertNotIn(cookie, blob)
            self.assertNotIn(history, blob)
            self.assertNotIn(password, blob)
            firefox = next(item for item in data["browsers"] if item["name"] == "firefox")
            self.assertTrue(firefox["installed"])
            self.assertIs(firefox["privacy"], False)

            (profile / "user.js").write_text(userjs, encoding="utf-8")
            ext = (
                home
                / ".config"
                / "google-chrome"
                / "Default"
                / "Extensions"
                / "cjpalhdlnbpafiamejdnhcphjbkeiagm"
            )
            ext.mkdir(parents=True)
            (home / ".config" / "google-chrome" / "Default" / "Cookies").write_text(
                chrome_cookie,
                encoding="utf-8",
            )
            data = browser.collect(home=home, system="Linux")
            blob = json.dumps(data)
            self.assertNotIn(userjs, blob)
            self.assertNotIn(chrome_cookie, blob)
            firefox = next(item for item in data["browsers"] if item["name"] == "firefox")
            chrome = next(item for item in data["browsers"] if item["name"] == "chrome")
            self.assertIs(firefox["privacy"], True)
            self.assertIs(chrome["privacy"], True)

    def test_source_does_not_name_secret_stores(self):
        text = Path("ghostleak/probes/browser.py").read_text(encoding="utf-8").lower()
        for banned in ("cookies.sqlite", "places.sqlite", "logins.json", "login data", "web data"):
            self.assertNotIn(banned, text)


if __name__ == "__main__":
    unittest.main()
