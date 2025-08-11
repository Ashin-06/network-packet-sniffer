pip install scapy
import importlib.metadata
print(importlib.metadata.version("scapy"))
from scapy.all import sniff

# Function to process packets
def packet_callback(packet):
    print(packet.summary())  # Print a brief summary of each packet

# Start sniffing
print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)  # Capture 10 packets
sniff(filter="tcp", prn=packet_callback, count=10)
sniff(filter="port 80", prn=packet_callback, count=10)
from scapy.all import IP

def detailed_packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Packet: {packet[IP].src} → {packet[IP].dst}, Protocol: {packet.proto}")

sniff(prn=detailed_packet_callback, count=10)
from scapy.all import wrpcap

packets = sniff(count=50)  # Capture 50 packets
wrpcap("captured_packets.pcap", packets)
print("Packets saved to captured_packets.pcap")
