# CodeAlpha_Basic_Network_Sniffer

Python Network Packet Sniffer

This project is a simple yet powerful network packet sniffer developed using Python and the Scapy library. It's designed to capture and display network traffic in real-time, providing a detailed, layered breakdown of each packet.

Features

Real-time Packet Capture: Sniffs network packets as they traverse the network interface.

Layered Protocol Analysis: Provides detailed breakdowns for:

Layer 2 (Data Link): Ethernet, ARP

Layer 3 (Network): IPv4, IPv6

Layer 4 (Transport): TCP, UDP, ICMP

Layer 7 (Application): DNS, Basic HTTP data

Color-coded Output: Uses colorama for enhanced readability, distinguishing different layers and information types in the console output.

Timestamping: Each packet display includes a precise timestamp.

Payload Inspection: Shows raw payload data in hexadecimal format, and attempts to decode it for HTTP traffic.

Error Handling: Includes basic error handling for common issues like insufficient privileges.

Requirements

Python 3.x

Scapy library

Colorama library

You can install the required libraries using pip. Note that depending on your system, you might need to install scapy with pip install scapy[basic] or pip install scapy[basic,complete] for full functionality.

How to Use

To run the packet sniffer, you must have administrator (root) privileges because capturing raw network packets requires special permissions.

Save the code: Save the provided Python code as a .py file (e.g., sniffer.py).

Open your terminal or command prompt.

Navigate to the directory where you saved the sniffer.py file.

Run the script using sudo (on Linux/macOS) or as an Administrator (on Windows). On Windows, open Command Prompt or PowerShell as an Administrator.

The sniffer will start displaying incoming network packets in real-time. To stop the sniffer, press CTRL+C.
