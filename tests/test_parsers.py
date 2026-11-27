"""Pure parsers for /proc, ss, netstat, ifconfig, and firewall text."""

from __future__ import annotations

import unittest

from ghostleak.parsers import (
    classify_addr,
    decode_le_ipv4,
    decode_le_ipv6,
    is_routable,
    is_vpn_iface,
    parse_alf,
    parse_gateway_text,
    parse_ifconfig,
    parse_ip_addr,
    parse_iptables,
    parse_netstat,
    parse_os_release,
    parse_proc_net,
    parse_proc_route,
    parse_resolv,
    parse_ss,
    parse_ufw,
)

NETSTAT_SAMPLE = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 10.1.2.3:8080           0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 ::1:631                 :::*                    LISTEN
udp        0      0 0.0.0.0:68              0.0.0.0:*
"""

SS_SAMPLE = """\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      128        127.0.0.1:5432      0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*
"""

IFCONFIG_SAMPLE = """\
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.30.0.2  netmask 255.255.255.0  broadcast 172.30.0.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>

wg0: flags=209<UP,POINTOPOINT,RUNNING,NOARP>  mtu 1420
        inet 10.8.0.2  netmask 255.255.255.0
"""

PROC_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000 100 0 0 10 0\n"
    "   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000 100 0 0 10 0\n"
    "   2: 0100007F:1538 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000 100 0 0 10 0\n"
)


class ParserTests(unittest.TestCase):
    def test_ipv4_decoder(self):
        self.assertEqual(decode_le_ipv4("00000000"), "0.0.0.0")
        self.assertEqual(decode_le_ipv4("0100007F"), "127.0.0.1")
        self.assertEqual(decode_le_ipv4("01001EAC"), "172.30.0.1")

    def test_ipv6_decoder(self):
        self.assertEqual(decode_le_ipv6("00" * 16), "::")
        self.assertEqual(decode_le_ipv6("00000000000000000000000001000000"), "::1")

    def test_proc_tcp_listen_only(self):
        rows = parse_proc_net(PROC_TCP, proto="tcp", ipv6=False)
        self.assertEqual(len(rows), 2)
        by_port = {row["port"]: row for row in rows}
        self.assertEqual(by_port[22]["addr"], "0.0.0.0")
        self.assertEqual(by_port[22]["scope"], "wildcard")
        self.assertEqual(by_port[5432]["addr"], "127.0.0.1")
        self.assertEqual(by_port[5432]["scope"], "loopback")

    def test_proc_route(self):
        text = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n"
        self.assertEqual(parse_proc_route(text), "192.168.1.1")

    def test_netstat_scopes(self):
        rows = {(row["addr"], row["port"]): row["scope"] for row in parse_netstat(NETSTAT_SAMPLE)}
        self.assertEqual(rows[("0.0.0.0", 22)], "wildcard")
        self.assertEqual(rows[("127.0.0.1", 5432)], "loopback")
        self.assertEqual(rows[("10.1.2.3", 8080)], "address")
        self.assertEqual(rows[("::", 22)], "wildcard")
        from ghostleak.parsers import format_endpoint

        self.assertEqual(format_endpoint("::", 22), "[::]:22")
        self.assertEqual(format_endpoint("::1", 631), "[::1]:631")
        self.assertEqual(format_endpoint("0.0.0.0", 22), "0.0.0.0:22")
        self.assertEqual(rows[("::1", 631)], "loopback")
        self.assertEqual(rows[("0.0.0.0", 68)], "wildcard")

    def test_ss_sample(self):
        rows = parse_ss(SS_SAMPLE)
        ports = sorted(row["port"] for row in rows)
        self.assertEqual(ports, [22, 68, 5432])

    def test_ifconfig_and_ip(self):
        ifaces = parse_ifconfig(IFCONFIG_SAMPLE)
        self.assertEqual(ifaces["lo"], ["127.0.0.1", "::1"])
        self.assertIn("172.30.0.2", ifaces["enp0s3"])
        self.assertIn("10.8.0.2", ifaces["wg0"])
        ip = parse_ip_addr("2: eth0    inet 10.1.2.3/24 scope global eth0\n2: wg0    inet 10.8.0.2/32 scope global wg0\n")
        self.assertEqual(ip["eth0"], ["10.1.2.3"])
        self.assertTrue(is_vpn_iface("wg0"))
        self.assertTrue(is_vpn_iface("tailscale0"))
        self.assertTrue(is_vpn_iface("utun3"))
        self.assertFalse(is_vpn_iface("eth0"))
        self.assertFalse(is_vpn_iface("docker0"))
        self.assertFalse(is_routable("127.0.0.1"))
        self.assertFalse(is_routable("fe80::1"))
        self.assertTrue(is_routable("10.1.2.3"))
        self.assertEqual(classify_addr("::"), "wildcard")

    def test_gateway_and_resolv_and_os_release(self):
        self.assertEqual(parse_gateway_text("default via 192.168.1.1 dev eth0\n"), "192.168.1.1")
        self.assertEqual(
            parse_gateway_text("0.0.0.0         172.30.0.1      0.0.0.0         UG\n"),
            "172.30.0.1",
        )
        self.assertEqual(
            parse_gateway_text("   gateway: 10.0.0.1\n"),
            "10.0.0.1",
        )
        dns = parse_resolv("# comment\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n")
        self.assertEqual(dns, ["1.1.1.1", "9.9.9.9"])
        parsed = parse_os_release('NAME="Ubuntu"\nID=ubuntu\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')
        self.assertEqual(parsed["ID"], "ubuntu")
        self.assertEqual(parsed["PRETTY_NAME"], "Ubuntu 24.04 LTS")

    def test_firewall_parsers(self):
        self.assertTrue(parse_ufw("Status: active\n"))
        self.assertFalse(parse_ufw("Status: inactive\n"))
        self.assertIsNone(parse_ufw("missing\n"))
        self.assertFalse(parse_iptables("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"))
        self.assertTrue(parse_iptables("-P INPUT DROP\n-P OUTPUT ACCEPT\n"))
        self.assertTrue(parse_iptables("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP\n"))
        self.assertTrue(parse_alf("Firewall is enabled. (State = 1)\n"))
        self.assertFalse(parse_alf("0\n"))


if __name__ == "__main__":
    unittest.main()
