"""The README is the install guide the project promises."""

from __future__ import annotations

import unittest
from pathlib import Path

from ghostleak import __version__
from ghostleak.score import WEIGHTS
from tests.support import ROOT


class ReadmeTests(unittest.TestCase):
    def test_readme_covers_platforms_and_privacy(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://github.com/gurung-dev/ghostleak-cli.git", text)
        for word in ("Termux", "Kali", "macOS", "--share", "--lang", "--json", "--no-color", "--export"):
            self.assertIn(word, text)
        self.assertIn("100%", text)
        self.assertIn("offline", text.lower())
        self.assertIn("[REDACTED]", text)
        for row in WEIGHTS:
            self.assertIn(row["code"], text)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{__version__}"', project)
        self.assertIn("dependencies = []", project)
        self.assertTrue((ROOT / "install.sh").is_file())
        self.assertNotIn("requirements.txt", text)


if __name__ == "__main__":
    unittest.main()
