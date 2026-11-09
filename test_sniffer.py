"""Parser tests. These build packets in memory, so they need no interface and no privileges."""
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6

import sniffer


def test_tcp_line_shows_ports_and_size():
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)
    line = sniffer.describe(pkt)
    assert "TCP" in line and "1.1.1.1:1234 -> 2.2.2.2:80" in line
    assert f"({len(pkt)} bytes)" in line


def test_udp_and_ipv6_and_non_ip():
    assert "UDP" in sniffer.describe(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5, dport=53))
    assert "::1:4000 -> ::2:80" in sniffer.describe(IPv6(src="::1", dst="::2") / TCP(sport=4000, dport=80))
    # A non-IP packet has no IP layer; it should still describe without raising.
    assert sniffer.describe(Ether() / (b"\x00" * 20))


def test_summary_counts_each_protocol():
    packets = [
        IP() / TCP(),
        IP() / TCP(),
        IP() / UDP(),
        IP() / ICMP(),
        Ether() / b"x",
    ]
    tally = sniffer.summarize(packets)
    assert tally["TCP"] == 2
    assert tally["UDP"] == 1
    assert tally["ICMP"] == 1


def test_selftest_passes():
    assert sniffer.selftest() == 0
