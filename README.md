# Network Packet Sniffer

A command-line network packet sniffing tool written in Python using the Scapy library. This script captures live network traffic on a specified interface and displays key information about each packet, such as IP addresses, ports, and payload data.

## Features

* Captures live network packets on a given interface.
* Parses IP layer information to show source and destination IPs.
* Identifies TCP/UDP protocols and displays source/destination ports.
* Prints the raw data payload of packets, if present.
* Uses `argparse` to easily accept a network interface from the command line.

## Technologies Used

* Python
* Scapy

## Setup and Usage

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Ashin-06/network-packet-sniffer.git](https://github.com/Ashin-06/network-packet-sniffer.git)
    cd network-packet-sniffer
    ```

2.  **Install Dependencies:**
    This project requires the Scapy library.
    ```bash
    pip install scapy
    ```

3.  **Find Your Network Interface:**
    You will need to know the name of the network interface you want to monitor (e.g., `eth0`, `en0`, `Wi-Fi`).
    * On Windows: `ipconfig`
    * On macOS/Linux: `ifconfig` or `ip a`

4.  **Run the Script:**
    Running a network sniffer requires administrator/root privileges.
    ```bash
    # Replace <interface_name> with your actual network interface
    sudo python packet_sniffer.py --interface <interface_name>
    ```

## ⚖️ Disclaimer

This tool is for educational purposes only. Only use it on networks that you own or have explicit permission to monitor. Unauthorized packet sniffing is illegal.