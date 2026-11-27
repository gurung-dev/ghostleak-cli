"""Secret names are reported. Secret values never enter a result."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from ghostleak.probes import env_audit
from ghostleak.redact import REDACTED, classify_name, sanitize_tree, scrub_text, sensitive_names


class RedactTests(unittest.TestCase):
    def test_name_classification(self):
        sensitive = [
            "AWS_SECRET_ACCESS_KEY",
            "AWS_DEFAULT_REGION",
            "GITHUB_TOKEN",
            "GITHUB_USER",
            "MY_API_TOKEN",
            "DATABASE_PASSWORD",
            "OPENAI_API_KEY",
            "DATABASE_URL",
            "aws_session_token",
        ]
        for name in sensitive:
            hit, reason = classify_name(name)
            self.assertTrue(hit, name)
            self.assertTrue(reason, name)
        safe = ["PATH", "HOME", "USER", "TERMUX_VERSION", "SSH_AUTH_SOCK", "LANG", "PUBLIC_KEY"]
        for name in safe:
            hit, _reason = classify_name(name)
            self.assertFalse(hit, name)

    def test_sensitive_names_never_copy_values(self):
        canary = "CANARY-ENV-SECRET-999aaa"
        env = {
            "PATH": "/usr/bin",
            "USER": "alice",
            "TERMUX_VERSION": "0.118",
            "MY_API_TOKEN": canary,
        }
        found = sensitive_names(env)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "MY_API_TOKEN")
        self.assertEqual(found[0]["value"], REDACTED)
        self.assertNotIn(canary, json.dumps(found))

    def test_scrub_replaces_long_secret_values(self):
        canary = "CANARY-SECRET-VALUE-9f3a"
        env = {"GHOSTLEAK_TEST_TOKEN": canary, "PATH": "/usr/bin"}
        text = f"before {canary} after"
        cleaned = scrub_text(text, env)
        self.assertNotIn(canary, cleaned)
        self.assertIn(REDACTED, cleaned)

    def test_sanitize_tree_forces_redaction(self):
        canary = "CANARY-TREE-SECRET-abcdef"
        node = {"name": "AWS_SECRET_ACCESS_KEY", "value": canary, "nested": [canary]}
        cleaned = sanitize_tree(node)
        self.assertEqual(cleaned["value"], REDACTED)
        # Nested free strings are not names; scrub_text is the second barrier.
        self.assertNotIn(canary, scrub_text(json.dumps(cleaned), {"AWS_SECRET_ACCESS_KEY": canary}))

    def test_history_and_key_bytes_are_not_read(self):
        canary_hist = "CANARY-HISTORY-SECRET-xyz123"
        canary_key = "CANARY-KEY-MATERIAL-abcdef123456"
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            history = home / ".bash_history"
            history.write_text(f"export AWS_SECRET_ACCESS_KEY={canary_hist}\n", encoding="utf-8")
            os.chmod(history, 0o644)
            ssh = home / ".ssh"
            ssh.mkdir()
            os.chmod(ssh, 0o755)
            key = ssh / "id_ed25519"
            key.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" + canary_key + "\n",
                encoding="utf-8",
            )
            os.chmod(key, 0o644)
            data = env_audit.collect(
                environ={"PATH": "/usr/bin", "HOME": str(home), "USER": "alice"},
                home=home,
            )
            blob = json.dumps(data)
            self.assertNotIn(canary_hist, blob)
            self.assertNotIn(canary_key, blob)
            self.assertNotIn("BEGIN OPENSSH", blob)
            self.assertTrue(data["histories"][0]["world_readable"])
            self.assertTrue(data["ssh"]["present"])
            self.assertTrue(any(item["path"].endswith("id_ed25519") for item in data["ssh"]["keys"]))
            self.assertNotIn(str(home), blob)
            self.assertTrue(data["histories"][0]["path"].startswith("~"))
            mode = stat.S_IMODE(history.stat().st_mode)
            self.assertEqual(data["histories"][0]["mode"], f"{mode:04o}")


if __name__ == "__main__":
    unittest.main()
