"""English and Nepali copy stay in sync and format cleanly."""

from __future__ import annotations

import unittest

from ghostleak.i18n import FINDINGS, describe, share_line, t
from ghostleak.score import WEIGHTS, Finding


PARAMS = {
    "wildcard_listener": {"count": 2, "examples": "tcp/0.0.0.0:22"},
    "interface_listener": {"count": 1, "examples": "tcp/10.0.0.5:8080"},
    "no_vpn": {},
    "sensitive_env": {"count": 1, "names": "AWS_SECRET_ACCESS_KEY"},
    "ssh_world_readable": {"paths": "~/.ssh (0755)", "mode": "0755"},
    "ssh_permissive": {"paths": "~/.ssh/id_ed25519 (0640)", "mode": "0640"},
    "history_world_readable": {"paths": "~/.bash_history (0644)"},
    "history_group_readable": {"paths": "~/.zsh_history (0640)"},
    "secret_file_exposed": {"paths": "~/.netrc (0644)", "count": 1},
    "secret_file_group": {"paths": "~/.pgpass (0640)", "count": 1},
    "config_world_writable": {"paths": "~/.bashrc (0666)", "count": 1},
    "firewall_off": {"tool": "ufw"},
    "firewall_unknown": {},
    "running_as_root": {},
    "browser_no_privacy": {"names": "chrome", "count": 1},
}


class I18nTests(unittest.TestCase):
    def test_languages_cover_the_same_findings(self):
        self.assertEqual(set(FINDINGS["en"]), set(FINDINGS["ne"]))
        weight_codes = {row["code"] for row in WEIGHTS}
        self.assertEqual(set(FINDINGS["en"]), weight_codes)
        for code in FINDINGS["en"]:
            self.assertEqual(
                set(FINDINGS["en"][code]["tips"]),
                {"termux", "darwin", "linux", "other"},
            )
            self.assertEqual(
                set(FINDINGS["ne"][code]["tips"]),
                {"termux", "darwin", "linux", "other"},
            )

    def test_placeholders_resolve(self):
        for code, params in PARAMS.items():
            finding = Finding(code, "low", 1, params)
            for lang in ("en", "ne"):
                for family in ("termux", "darwin", "linux", "other"):
                    title, tip = describe(finding, lang, family, "ubuntu")
                    self.assertNotIn("{", title, f"{lang} {code} {family} title")
                    self.assertNotIn("{", tip, f"{lang} {code} {family} tip")
                    self.assertTrue(title)
                    self.assertTrue(tip)

    def test_kali_extra_is_translated(self):
        finding = Finding("wildcard_listener", "moderate", 8, PARAMS["wildcard_listener"])
        _title, tip = describe(finding, "en", "linux", "kali")
        self.assertIn("Kali", tip)
        _title, tip_ne = describe(finding, "ne", "linux", "kali")
        self.assertIn("काली", tip_ne)

    def test_share_line_contract(self):
        self.assertEqual(share_line("en", 74, "HIGH"), "GhostLeak CLI Score: 74/100 [HIGH]")
        self.assertEqual(share_line("ne", 74, "HIGH"), "GhostLeak CLI स्कोर: 74/100 [उच्च]")

    def test_ui_labels_differ_by_language(self):
        self.assertIn("Fingerprint", t("en", "probe.os"))
        self.assertEqual(t("en", "findings"), "findings")
        self.assertIn("एक्सपोजर", t("ne", "exposure"))
        self.assertIn("जोखिम", t("ne", "weights_hint"))
        self.assertIn("फायरवाल", t("ne", "probe.firewall"))
        self.assertEqual(t("ne", "tier.CRITICAL"), "गम्भीर")
        self.assertEqual(t("en", "tier.LOW"), "LOW")


if __name__ == "__main__":
    unittest.main()
