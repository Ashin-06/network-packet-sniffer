"""Live network packet sniffer.

Captures packets on a network interface and prints a readable, one-line summary of
each, then a protocol breakdown at the end. Read-only: it observes traffic, it never
sends anything. Capturing live traffic needs administrator/root privileges.

    sudo python sniffer.py --interface eth0 --count 20
    sudo python sniffer.py --filter "tcp port 443" --output capture.pcap
    python sniffer.py --selftest        # parse built-in packets, no privileges needed
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, sniff, wrpcap

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def describe(packet) -> str:
    """One readable line for a packet: time, protocol, endpoints and size."""
    stamp = datetime.now().strftime("%H:%M:%S")
    if packet.haslayer(IP):
        net = packet[IP]
        src, dst, proto = net.src, net.dst, PROTO_NAMES.get(net.proto, str(net.proto))
    elif packet.haslayer(IPv6):
        net = packet[IPv6]
        src, dst, proto = net.src, net.dst, PROTO_NAMES.get(net.nh, str(net.nh))
    else:
        return f"{stamp}  {packet.summary()}"

    if packet.haslayer(TCP):
        proto, seg = "TCP", packet[TCP]
        src, dst = f"{src}:{seg.sport}", f"{dst}:{seg.dport}"
    elif packet.haslayer(UDP):
        proto, seg = "UDP", packet[UDP]
        src, dst = f"{src}:{seg.sport}", f"{dst}:{seg.dport}"
    return f"{stamp}  {proto:<5} {src} -> {dst}  ({len(packet)} bytes)"


def protocol_of(packet) -> str:
    """The protocol label used for the end-of-run tally."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        return "other IP"
    return packet.lastlayer().name


def summarize(packets) -> Counter:
    """Count packets per protocol."""
    return Counter(protocol_of(p) for p in packets)


def _print_summary(tally: Counter) -> None:
    total = sum(tally.values())
    print(f"\nCaptured {total} packet(s).")
    for proto, n in tally.most_common():
        share = (n / total * 100) if total else 0
        print(f"  {proto:<10} {n:>5}  ({share:4.1f}%)")


def _build_examples() -> list:
    """A few packets made in memory, so the parser can be exercised without capturing."""
    return [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=443),
        Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=52000, dport=53),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Ether() / IPv6(src="::1", dst="::2") / TCP(sport=4000, dport=80),
        Ether() / b"not an IP packet",
    ]


def selftest() -> int:
    packets = _build_examples()
    lines = [describe(p) for p in packets]
    for line in lines:
        print(line)
    assert "TCP   10.0.0.1:51000 -> 10.0.0.2:443" in lines[0]
    assert "UDP   10.0.0.2:52000 -> 8.8.8.8:53" in lines[1]
    assert "ICMP  10.0.0.1 -> 10.0.0.2" in lines[2]
    assert "TCP   ::1:4000 -> ::2:80" in lines[3]
    tally = summarize(packets)
    assert tally["TCP"] == 2 and tally["UDP"] == 1 and tally["ICMP"] == 1, tally
    _print_summary(tally)
    print("\nself-test passed")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Capture and summarize live network traffic (read-only).")
    parser.add_argument("-i", "--interface", help="network interface, e.g. eth0 or Wi-Fi (default: Scapy's default)")
    parser.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 443"')
    parser.add_argument("-c", "--count", type=int, default=0, help="number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-t", "--timeout", type=int, help="stop after this many seconds")
    parser.add_argument("-o", "--output", help="also write the captured packets to a .pcap file")
    parser.add_argument("--selftest", action="store_true", help="parse built-in packets and exit (no privileges needed)")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    captured = []

    def on_packet(packet):
        captured.append(packet)
        print(describe(packet))

    where = args.interface or "the default interface"
    stop = f"{args.count} packets" if args.count else "Ctrl+C"
    print(f"Sniffing on {where} (filter: {args.filter or 'none'}). Stopping after {stop}.")
    try:
        sniff(prn=on_packet, iface=args.interface, filter=args.filter, count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("Capturing traffic needs privileges. Re-run with sudo (Linux/macOS) or as Administrator (Windows).")
    except OSError as exc:
        sys.exit(f"Could not capture on {where}: {exc}")

    _print_summary(summarize(captured))
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"Saved {len(captured)} packet(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
