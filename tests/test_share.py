"""--share prints the score line and nothing that identifies the host."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ghostleak.cli import main
from ghostleak.i18n import share_line
from ghostleak.score import collect_ghost_signals, machine_ghost_id
from tests.support import assert_absent, assert_no_secret_values


def _run(argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _identifiers():
    needles = []
    try:
        host = os.uname().nodename
    except Exception:
        host = ""
    if host:
        needles.append(host)
    user = os.environ.get("USER") or ""
    if len(user) >= 3:
        needles.append(user)
    home = os.environ.get("HOME") or ""
    if home:
        needles.append(home)
    ghost, _sources = machine_ghost_id(collect_ghost_signals())
    needles.append(ghost)
    machine_id = ""
    try:
        machine_id = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        machine_id = ""
    if machine_id:
        needles.append(machine_id)
    return needles


class ShareTests(unittest.TestCase):
    def test_share_text_is_generic(self):
        code, out, _err = _run(["--share", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("GhostLeak CLI Score:", out)
        self.assertRegex(
            out,
            r"GhostLeak CLI Score: \d+/100 \[(LOW|MODERATE|HIGH|CRITICAL)\]",
        )
        # The line inside the block must match the contract exactly.
        score_lines = [line.strip() for line in out.splitlines() if line.startswith("GhostLeak CLI Score:")]
        self.assertEqual(len(score_lines), 1)
        self.assertRegex(
            score_lines[0],
            r"^GhostLeak CLI Score: \d+/100 \[(LOW|MODERATE|HIGH|CRITICAL)\]$",
        )
        assert_absent(out, _identifiers(), "share")
        assert_no_secret_values(out, label="share")
        for token in ("ghost id", "hostname", "0.0.0.0", "127.0.0.1", "enp", "tun"):
            self.assertNotIn(token, out.lower())

    def test_share_json_keys_are_minimal(self):
        code, out, _err = _run(["--share", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data.keys()), {"score", "risk_tier", "summary"})
        self.assertEqual(data["summary"], share_line("en", data["score"], data["risk_tier"]))
        self.assertNotIn("ghost_id", data)
        assert_absent(out, _identifiers(), "share-json")
        assert_no_secret_values(out, label="share-json")

    def test_share_export_stays_generic(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "share.md")
            code, out, err = _run(["--share", "--no-color", "--export", path])
            self.assertEqual(code, 0)
            body = Path(path).read_text(encoding="utf-8")
        self.assertIn("GhostLeak CLI Score:", body)
        self.assertIn("ghostleak: wrote", err)
        assert_absent(body, _identifiers(), "share-export")
        assert_absent(out, _identifiers(), "share-stdout")
        assert_no_secret_values(body, label="share-export")


if __name__ == "__main__":
    unittest.main()
