"""Missing commands, timeouts, and Termux detection must not crash."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ghostleak import safe
from ghostleak.probes import firewall, network, os_fingerprint, ports


class FallbackTests(unittest.TestCase):
    def test_missing_binary_is_not_available(self):
        code, out, err = safe.run_cmd(["ghostleak-missing-binary-xyz"])
        self.assertIsNone(code)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_disallowed_command_never_runs(self):
        called = []

        def boom(*_args, **_kwargs):
            called.append(True)
            raise AssertionError("subprocess should not run")

        with mock.patch("ghostleak.safe.subprocess.run", boom):
            code, _out, _err = safe.run_cmd(["curl", "https://example.invalid"])
        self.assertIsNone(code)
        self.assertEqual(called, [])

    def test_timeout_is_swallowed(self):
        def boom(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="ss", timeout=1)

        with mock.patch("ghostleak.safe.subprocess.run", boom):
            code, _out, _err = safe.run_cmd(["ss", "-l"])
        self.assertIsNone(code)

    def test_termux_fingerprint(self):
        info = os_fingerprint.collect(
            environ={"TERMUX_VERSION": "0.118.0", "LANG": "en_US.UTF-8"},
            run=lambda *_a, **_k: (None, "", ""),
        )
        self.assertTrue(info["termux"])
        self.assertEqual(info["family"], "termux")
        self.assertEqual(info["status"], "ok")

    def test_termux_firewall_skips_commands(self):
        def run(*_args, **_kwargs):
            raise AssertionError("firewall command should not run on Termux")

        result = firewall.collect(environ={"TERMUX_VERSION": "1"}, run=run)
        self.assertTrue(result["termux"])
        self.assertIsNone(result["active"])
        self.assertEqual(result["status"], "not_available")

    def test_proc_port_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc"
            net = proc / "net"
            net.mkdir(parents=True)
            (net / "tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000 100 0 0 10 0\n",
                encoding="utf-8",
            )

            def no_cmd(*_args, **_kwargs):
                return None, "", ""

            result = ports.collect(run=no_cmd, proc_root=proc)
        self.assertEqual(result["method"], "proc")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["listeners"][0]["port"], 22)
        self.assertEqual(result["listeners"][0]["scope"], "wildcard")

    def test_ss_preferred_over_proc(self):
        sample = "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"

        def fake(argv, timeout=3.0):
            if argv and os.path.basename(argv[0]) == "ss":
                return 0, sample, ""
            return None, "", ""

        result = ports.collect(run=fake, proc_root=Path("/this/does/not/exist"))
        self.assertEqual(result["method"], "ss")
        self.assertEqual(result["listeners"][0]["scope"], "loopback")
        self.assertEqual(result["listeners"][0]["port"], 5432)

    def test_network_injected_files_and_redacted_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            resolv = root / "resolv.conf"
            resolv.write_text("nameserver 1.1.1.1\n", encoding="utf-8")
            route = root / "route"
            route.write_text(
                "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n",
                encoding="utf-8",
            )

            def run(argv, timeout=3.0):
                if argv and argv[0] == "ip" and "addr" in argv:
                    return (
                        0,
                        "2: eth0    inet 10.1.2.3/24 scope global eth0\n"
                        "3: wg0    inet 10.8.0.2/24 scope global wg0\n",
                        "",
                    )
                return None, "", ""

            secret = "http://user:SECRETPROXYVALUE@10.0.0.1:8080"
            result = network.collect(
                environ={"https_proxy": secret, "LANG": "C"},
                run=run,
                resolv_path=resolv,
                route_path=route,
                sysfs_net=root / "no-sysfs",
            )
        self.assertIn("1.1.1.1", result["dns"])
        self.assertEqual(result["gateway"], "192.168.1.1")
        self.assertIn("wg0", result["vpn_interfaces"])
        self.assertEqual(result["proxy_vars"], ["https_proxy"])
        self.assertNotIn(secret, json_dumps(result))
        self.assertNotIn("SECRETPROXYVALUE", json_dumps(result))

    def test_network_missing_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = network.collect(
                environ={},
                run=lambda *_a, **_k: (None, "", ""),
                resolv_path=root / "missing-resolv",
                route_path=root / "missing-route",
                sysfs_net=root / "missing-sys",
            )
        self.assertIn(result["status"], {"not_available", "restricted"})
        self.assertEqual(result["interfaces"], [])

    def test_android_dns_getprop(self):
        def run(argv, timeout=3.0):
            if list(argv)[:2] == ["getprop", "net.dns1"]:
                return 0, "8.8.8.8\n", ""
            return None, "", ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "resolv.conf"
            empty.write_text("# no servers\n", encoding="utf-8")
            result = network.collect(
                environ={"TERMUX_VERSION": "1"},
                run=run,
                resolv_path=empty,
                route_path=root / "no-route",
                sysfs_net=root / "no-sys",
            )
        self.assertIn("8.8.8.8", result["dns"])

    def test_guard_swallows_exceptions(self):
        def boom():
            raise RuntimeError("nope")

        result = safe.guard_probe(boom)
        self.assertEqual(result["status"], "restricted")
        self.assertNotIn("nope", json_dumps(result))


def json_dumps(value) -> str:
    import json

    return json.dumps(value)


if __name__ == "__main__":
    unittest.main()
