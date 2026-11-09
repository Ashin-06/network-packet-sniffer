# Network Packet Sniffer

A command-line network traffic sniffer written in Python with [Scapy](https://scapy.net/).
It captures live packets on an interface and prints a readable one-line summary of each
— time, protocol, source and destination (with ports for TCP/UDP), and size — then a
protocol breakdown when it stops. It is read-only: it observes traffic and never sends
anything.

A learning project for understanding how packets look on the wire, in the spirit of
`tcpdump` and Wireshark.

## Features

- Live capture on a chosen interface, with an optional BPF filter (e.g. `tcp port 443`).
- Readable per-packet lines for IPv4, IPv6, TCP, UDP and ICMP; other packets fall back to Scapy's summary.
- A protocol tally at the end, with percentages.
- Optional save to a `.pcap` file to open later in Wireshark.
- A `--selftest` that parses built-in packets, so you can check the code without capturing.

## Setup

```bash
git clone https://github.com/Ashin-06/network-packet-sniffer.git
cd network-packet-sniffer
pip install -r requirements.txt
```

## Usage

Capturing live traffic needs privileges: run with `sudo` on Linux/macOS, or in an
Administrator terminal on Windows (with [Npcap](https://npcap.com/) installed).

```bash
sudo python sniffer.py --interface eth0 --count 20
sudo python sniffer.py --filter "tcp port 443" --output capture.pcap
python sniffer.py --selftest        # no privileges needed
```

| Option | Meaning |
|---|---|
| `-i`, `--interface` | interface to capture on, e.g. `eth0`, `Wi-Fi` |
| `-f`, `--filter` | BPF filter, e.g. `"udp port 53"` |
| `-c`, `--count` | number of packets to capture (`0` = until Ctrl+C) |
| `-t`, `--timeout` | stop after this many seconds |
| `-o`, `--output` | also write captured packets to a `.pcap` file |

To find an interface name: `ipconfig` on Windows, `ip a` or `ifconfig` on Linux/macOS.

## Tests

```bash
pip install pytest
python -m pytest -q
```

The tests build packets in memory, so they need no network interface and no privileges.

## Note on use

Only capture traffic on networks you own or are authorized to monitor. Intercepting
other people's traffic without permission is illegal in most places. This project is
for learning on your own machine or lab network.

## License

MIT — see [LICENSE](LICENSE).
