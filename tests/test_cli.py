"""CLI flags: language, JSON, color, export, and a crashing probe."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from ghostleak import __version__
from ghostleak.cli import main
from ghostleak.score import WEIGHTS
from tests.support import ROOT, assert_absent, assert_no_secret_values

CANARY = "CANARY-SECRET-VALUE-9f3a"


def _run(argv, env_updates=None):
    stdout = io.StringIO()
    stderr = io.StringIO()
    old = {}
    env_updates = env_updates or {}
    for key, value in env_updates.items():
        old[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
    finally:
        for key, previous in old.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_help_and_version(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("ghostleak", stdout.getvalue().lower())
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["--lang", "fr"])
        self.assertEqual(ctx.exception.code, 2)

    def test_nepali_dashboard(self):
        code, out, _err = _run(["--lang", "ne", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("एक्सपोजर", out)
        self.assertIn("निष्कर्ष", out)
        self.assertTrue(any(word in out for word in ("न्यून", "मध्यम", "उच्च", "गम्भीर")))
        assert_no_secret_values(out, label="nepali")

    def test_english_dashboard_is_not_nepali(self):
        code, out, _err = _run(["--lang", "en", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("GHOSTLEAK", out)
        self.assertIn("exposure", out.lower())
        self.assertNotIn("एक्सपोजर", out)
        self.assertNotIn("\033", out)
        for glyph in ("█", "░", "─", "╭"):
            self.assertNotIn(glyph, out)

    def test_default_color_when_no_color_unset(self):
        code, out, _err = _run(["--lang", "en"], env_updates={"NO_COLOR": None})
        self.assertEqual(code, 0)
        self.assertIn("\033", out)

    def test_json_redacts_and_parses(self):
        code, out, _err = _run(
            ["--json"],
            env_updates={"GHOSTLEAK_CANARY_TOKEN": CANARY},
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["tool"], "ghostleak-cli")
        self.assertEqual(data["version"], __version__)
        self.assertTrue(data["offline"])
        self.assertFalse(data["network_calls"])
        self.assertTrue(data["secrets_redacted"])
        self.assertIn(data["risk_tier"], {"LOW", "MODERATE", "HIGH", "CRITICAL"})
        self.assertEqual(data["risk_tier_label"], data["risk_tier"])
        self.assertEqual(len(data["ghost_id"]), 64)
        self.assertEqual(data["weights"], WEIGHTS)
        self.assertNotIn(CANARY, out)
        assert_no_secret_values(out, label="json")
        names = [item["name"] for item in data["environment"]["sensitive"]]
        self.assertIn("GHOSTLEAK_CANARY_TOKEN", names)
        for item in data["environment"]["sensitive"]:
            self.assertEqual(item["value"], "[REDACTED]")

    def test_json_nepali_label(self):
        code, out, _err = _run(["--json", "--lang", "ne"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn(data["risk_tier"], {"LOW", "MODERATE", "HIGH", "CRITICAL"})
        self.assertIn(data["risk_tier_label"], {"न्यून", "मध्यम", "उच्च", "गम्भीर"})
        self.assertNotEqual(data["risk_tier_label"], data["risk_tier"])

    def test_export_markdown_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            md_path = str(Path(tmp) / "report.md")
            json_path = str(Path(tmp) / "report.json")
            code, _out, err = _run(
                ["--no-color", "--export", md_path],
                env_updates={"GHOSTLEAK_CANARY_TOKEN": CANARY},
            )
            self.assertEqual(code, 0)
            self.assertIn("wrote", err)
            md = Path(md_path).read_text(encoding="utf-8")
            self.assertIn("GhostLeak CLI report", md)
            self.assertIn("wildcard_listener", md)
            self.assertNotIn(CANARY, md)
            assert_no_secret_values(md, label="markdown")
            code, out, _err = _run(
                ["--json", "--export", json_path],
                env_updates={"GHOSTLEAK_CANARY_TOKEN": CANARY},
            )
            self.assertEqual(code, 0)
            saved = json.loads(Path(json_path).read_text(encoding="utf-8"))
            self.assertEqual(saved["score"], json.loads(out)["score"])
            self.assertNotIn(CANARY, Path(json_path).read_text(encoding="utf-8"))

    def test_crashing_probe_still_finishes(self):
        with mock.patch(
            "ghostleak.probes.os_fingerprint.collect",
            side_effect=RuntimeError("boom"),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["--json", "--no-color"])
        self.assertEqual(code, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["os"]["status"], "restricted")
        self.assertNotIn("boom", stdout.getvalue())

    def test_script_entrypoint(self):
        env = os.environ.copy()
        env["GHOSTLEAK_CANARY_TOKEN"] = CANARY
        env["NO_COLOR"] = "1"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "ghostleak.py"), "--share", "--no-color"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("GhostLeak CLI Score:", proc.stdout)
        self.assertNotIn(CANARY, proc.stdout)
        assert_no_secret_values(proc.stdout, env, label="entrypoint")
        assert_absent(proc.stdout, [CANARY], "entrypoint")


if __name__ == "__main__":
    unittest.main()
