#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR

import datetime
from colorama import init, Fore, Style

init(autoreset=True)

COLORS = {
    "info": Fore.CYAN,
    "l2": Fore.YELLOW,
    "l3": Fore.GREEN,
    "l4": Fore.BLUE,
    "app": Fore.MAGENTA,
    "payload": Fore.LIGHTBLACK_EX,
    "error": Fore.RED
}

def format_payload(payload):
    try:
        decoded_payload = payload.decode('utf-8', errors='replace')
        return f"\n{COLORS['payload']}{decoded_payload}"
    except Exception:
        return f"\n{COLORS['payload']}{scapy.hexdump(payload, dump=True)}"

def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    print(f"\n{'-'*30} {COLORS['info']}[ {timestamp} ]{Style.RESET_ALL} {'-'*30}")

    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        print(f"{COLORS['l2']}[L2: Ethernet] Source MAC: {eth_layer.src} -> Destination MAC: {eth_layer.dst}")
    
    if packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        op_type = "Request (Who has?)" if arp_layer.op == 1 else "Reply (Is at)"
        print(f"{COLORS['l2']}[L2: ARP]       Operation: {op_type} | IP: {arp_layer.psrc} -> MAC: {arp_layer.hwsrc}")
        return

    ip_layer = None
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"{COLORS['l3']}[L3: IPv4]      Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst} | Protocol: {ip_layer.proto} | TTL: {ip_layer.ttl}")
    elif packet.haslayer(IPv6):
        ip_layer = packet.getlayer(IPv6)
        print(f"{COLORS['l3']}[L3: IPv6]      Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst} | Next Header: {ip_layer.nh}")
    else:
        return

    proto_layer = None
    if packet.haslayer(TCP):
        proto_layer = packet.getlayer(TCP)
        flags = proto_layer.flags.flagrepr()
        print(f"{COLORS['l4']}[L4: TCP]       Source Port: {proto_layer.sport} -> Destination Port: {proto_layer.dport} | Flags: {flags}")
    elif packet.haslayer(UDP):
        proto_layer = packet.getlayer(UDP)
        print(f"{COLORS['l4']}[L4: UDP]       Source Port: {proto_layer.sport} -> Destination Port: {proto_layer.dport} | Length: {proto_layer.len}")
    elif packet.haslayer(ICMP):
        proto_layer = packet.getlayer(ICMP)
        print(f"{COLORS['l4']}[L4: ICMP]      Type: {proto_layer.type} | Code: {proto_layer.code}")

    if proto_layer and proto_layer.payload:
        payload = proto_layer.payload
        
        if packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.opcode == 0 and dns_layer.qr == 0:
                query_name = dns_layer[DNSQR].qname.decode()
                print(f"{COLORS['app']}[L7: DNS]       Query: {query_name}")
            elif dns_layer.qr == 1:
                print(f"{COLORS['app']}[L7: DNS]       Answer:")
                for i in range(dns_layer.ancount):
                    dns_rr = dns_layer[DNSRR][i]
                    print(f"\t\t- {dns_rr.rrname.decode()} -> {dns_rr.rdata}")
        
        elif (packet.haslayer(TCP)) and (proto_layer.sport == 80 or proto_layer.dport == 80):
             print(f"{COLORS['app']}[L7: HTTP Data]")
             print(format_payload(bytes(payload)))
        
        else:
            print(f"{COLORS['payload']}[Payload (Raw Data)] Size: {len(payload)} bytes")
            print(scapy.hexdump(payload, dump=True))


def main():
    print(f"{COLORS['info']}### Fully Functional Sniffer Starting... ###")
    print(f"{COLORS['info']}Press CTRL+C to stop.")
    
    try:
        scapy.sniff(
            prn=packet_callback,
            store=0
        )
    except PermissionError:
        print(f"{COLORS['error']}[ERROR] Administrator (root) privileges are required to run the sniffer.")
        print(f"{COLORS['error']}Please run the script with 'sudo python3 <filename>.py' or as an administrator.")
    except Exception as e:
        print(f"{COLORS['error']}[Unexpected Error] {e}")
    finally:
        print(f"\n{COLORS['info']}### Sniffer stopped. ###")

if __name__ == "__main__":
    main()