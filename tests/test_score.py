"""Offline exposure scoring, tier boundaries, and the ghost id."""

from __future__ import annotations

import unittest

from ghostleak.score import (
    TIERS,
    WEIGHTS,
    Finding,
    analyze,
    exposure_score,
    machine_ghost_id,
    risk_tier,
    scaled_points,
)
from tests.support import empty_sections


class ScoreTests(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(risk_tier(0), "LOW")
        self.assertEqual(risk_tier(24), "LOW")
        self.assertEqual(risk_tier(25), "MODERATE")
        self.assertEqual(risk_tier(49), "MODERATE")
        self.assertEqual(risk_tier(50), "HIGH")
        self.assertEqual(risk_tier(74), "HIGH")
        self.assertEqual(risk_tier(75), "CRITICAL")
        self.assertEqual(risk_tier(100), "CRITICAL")

    def test_tier_table_matches_function(self):
        for row in TIERS:
            self.assertEqual(risk_tier(row["min"]), row["tier"])
            self.assertEqual(risk_tier(row["max"]), row["tier"])

    def test_score_is_capped_at_100(self):
        findings = [
            Finding("a", "critical", 80, {}),
            Finding("b", "critical", 80, {}),
        ]
        self.assertEqual(exposure_score(findings), 100)

    def test_clean_machine_is_low(self):
        findings = analyze(empty_sections())
        self.assertEqual(findings, [])
        self.assertEqual(exposure_score(findings), 0)
        self.assertEqual(risk_tier(0), "LOW")

    def test_wildcard_cap(self):
        sections = empty_sections()
        sections["ports"]["listeners"] = [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 1000 + i, "scope": "wildcard"}
            for i in range(10)
        ]
        findings = analyze(sections)
        wild = [item for item in findings if item.code == "wildcard_listener"]
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0].points, 24)
        self.assertEqual(wild[0].points, scaled_points("wildcard_listener", 10))
        self.assertNotIn("secret-host", str(wild[0].params))

    def test_loopback_listener_is_not_scored(self):
        sections = empty_sections()
        sections["ports"]["listeners"] = [
            {"proto": "tcp", "addr": "127.0.0.1", "port": 5432, "scope": "loopback"}
        ]
        self.assertEqual(analyze(sections), [])

    def test_sensitive_env_cap(self):
        sections = empty_sections()
        sections["env"]["sensitive"] = [
            {"name": f"SERVICE_{i}_TOKEN", "value": "[REDACTED]", "reason": "credential-like name"}
            for i in range(20)
        ]
        findings = analyze(sections)
        sens = [item for item in findings if item.code == "sensitive_env"]
        self.assertEqual(sens[0].points, 15)
        self.assertNotIn("super-secret", str(sens[0].params))

    def test_no_vpn_and_vpn_suppression(self):
        sections = empty_sections()
        sections["network"]["interfaces"].append(
            {"name": "eth0", "addresses": ["10.0.0.5"]}
        )
        findings = analyze(sections)
        self.assertTrue(any(item.code == "no_vpn" and item.points == 6 for item in findings))

        sections["network"]["vpn_interfaces"] = ["wg0"]
        sections["network"]["interfaces"].append(
            {"name": "wg0", "addresses": ["10.8.0.2"]}
        )
        findings = analyze(sections)
        self.assertFalse(any(item.code == "no_vpn" for item in findings))

    def test_firewall_and_root(self):
        sections = empty_sections()
        sections["firewall"]["active"] = False
        sections["firewall"]["tool"] = "ufw"
        sections["os"]["is_root"] = True
        findings = analyze(sections)
        codes = {item.code: item.points for item in findings}
        self.assertEqual(codes["firewall_off"], 15)
        self.assertEqual(codes["running_as_root"], 12)

    def test_firewall_unknown_and_termux_skip(self):
        sections = empty_sections()
        sections["firewall"]["active"] = None
        findings = analyze(sections)
        self.assertEqual(
            sum(item.points for item in findings if item.code == "firewall_unknown"),
            4,
        )
        sections["os"]["termux"] = True
        sections["firewall"]["termux"] = True
        findings = analyze(sections)
        self.assertFalse(any(item.code == "firewall_unknown" for item in findings))
        self.assertFalse(any(item.code == "firewall_off" for item in findings))

    def test_ssh_history_and_secret_files(self):
        sections = empty_sections()
        sections["env"]["ssh"] = {
            "present": True,
            "path": "~/.ssh",
            "mode": "0755",
            "world_readable": True,
            "world_writable": False,
            "group_readable": True,
            "keys": [],
        }
        sections["env"]["histories"] = [
            {
                "path": "~/.bash_history",
                "present": True,
                "mode": "0644",
                "world_readable": True,
                "group_readable": True,
            }
        ]
        sections["env"]["secret_files"] = [
            {
                "path": "~/.netrc",
                "present": True,
                "mode": "0644",
                "world_readable": True,
                "group_readable": True,
            },
            {
                "path": "~/.pgpass",
                "present": True,
                "mode": "0644",
                "world_readable": True,
                "group_readable": True,
            },
            {
                "path": "~/.npmrc",
                "present": True,
                "mode": "0644",
                "world_readable": True,
                "group_readable": True,
            },
        ]
        findings = analyze(sections)
        codes = {item.code: item.points for item in findings}
        self.assertEqual(codes["ssh_world_readable"], 12)
        self.assertEqual(codes["history_world_readable"], 8)
        self.assertEqual(codes["secret_file_exposed"], 20)

    def test_browser_cap(self):
        sections = empty_sections()
        sections["browser"]["browsers"] = [
            {"name": f"browser{i}", "installed": True, "privacy": False} for i in range(4)
        ]
        findings = analyze(sections)
        browser = [item for item in findings if item.code == "browser_no_privacy"]
        self.assertEqual(browser[0].points, 9)

    def test_unknown_privacy_is_not_penalised(self):
        sections = empty_sections()
        sections["browser"]["browsers"] = [
            {"name": "safari", "installed": True, "privacy": None}
        ]
        self.assertEqual(analyze(sections), [])

    def test_ghost_id_is_stable_and_hides_material(self):
        material = "UNIQUE-MACHINE-ID-ABCDEF-0123456789"
        first, sources = machine_ghost_id(
            [("machine-id", material), ("arch", "x86_64")]
        )
        second, _sources = machine_ghost_id(
            [("machine-id", material), ("arch", "x86_64")]
        )
        changed, _sources = machine_ghost_id(
            [("machine-id", material + "X"), ("arch", "x86_64")]
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertEqual(len(first), 64)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in first))
        self.assertNotIn(material, first)
        self.assertEqual(sources, ["machine-id", "arch"])

    def test_weights_cover_positive_points(self):
        for row in WEIGHTS:
            self.assertGreater(row["points"], 0)
            self.assertGreaterEqual(row["cap"], row["points"])
            self.assertEqual(scaled_points(row["code"], 1), row["points"])


if __name__ == "__main__":
    unittest.main()
