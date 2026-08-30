"""
packet_capture.py
-----------------
Module 1 - Packet Monitoring

This program captures live network packets using Scapy and
displays basic packet information.

Author : Shraavanth
"""

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, conf, Raw
from config import INTERFACE, PACKET_LIMIT, LOG_FILE
from database import init_database, insert_packet, DB_FILE
from packet_parser import parse_packet
import sys


def packet_callback(packet, log_file_handle):
    """
    This function is automatically called by Scapy
    whenever a packet is captured. Logs packet info to console,
    log file, and database. Handles multiple packet layer types.
    """

    output_lines = []
    packet_info = {}
    
    # Determine packet layer type and extract relevant information
    if packet.haslayer(ARP):
        # ARP Layer
        output_lines = _handle_arp_packet(packet)
        packet_info = {'layer': 'ARP'}
        
    elif packet.haslayer(IP):
        # IPv4 Layer - check for higher layer protocols
        if packet.haslayer(TCP):
            # TCP Layer
            output_lines = _handle_tcp_packet(packet)
            packet_info = {'layer': 'TCP'}
            
        elif packet.haslayer(UDP):
            # UDP Layer - check for DNS
            if packet.haslayer(DNS):
                # DNS Layer (typically on UDP port 53)
                output_lines = _handle_dns_packet(packet)
                packet_info = {'layer': 'DNS'}
            else:
                # Generic UDP Layer
                output_lines = _handle_udp_packet(packet)
                packet_info = {'layer': 'UDP'}
                
        elif packet.haslayer(ICMP):
            # ICMP Layer
            output_lines = _handle_icmp_packet(packet)
            packet_info = {'layer': 'ICMP'}
            
        else:
            # IPv4 with Unknown upper layer protocol
            output_lines = _handle_ip_packet(packet)
            packet_info = {'layer': 'IPv4'}
            
    elif packet.haslayer(IPv6):
        # IPv6 Layer - check for higher layer protocols
        if packet.haslayer(TCP):
            # TCP Layer over IPv6
            output_lines = _handle_tcp_packet(packet)
            packet_info = {'layer': 'TCP'}
            
        elif packet.haslayer(UDP):
            # UDP Layer over IPv6 - check for DNS
            if packet.haslayer(DNS):
                # DNS Layer over IPv6
                output_lines = _handle_dns_packet(packet)
                packet_info = {'layer': 'DNS'}
            else:
                # Generic UDP Layer over IPv6
                output_lines = _handle_udp_packet(packet)
                packet_info = {'layer': 'UDP'}
                
        elif packet.haslayer(ICMP):
            # ICMPv6 Layer
            output_lines = _handle_icmp_packet(packet)
            packet_info = {'layer': 'ICMPv6'}
            
        else:
            # IPv6 with Unknown upper layer protocol
            output_lines = _handle_ipv6_packet(packet)
            packet_info = {'layer': 'IPv6'}
            
    else:
        # Unknown packet type
        output_lines = _handle_unknown_packet(packet)
        packet_info = {'layer': 'Unknown'}
    
    # Print to console
    for line in output_lines:
        print(line)
    
    # Write to log file
    for line in output_lines:
        log_file_handle.write(line + "\n")
    log_file_handle.flush()  # Ensure data is written immediately
    
    # Insert into database
    try:
        packet_data = parse_packet(packet)
        insert_packet(packet_data)
    except Exception as e:
        print(f"Error inserting packet into database: {e}")


def _handle_arp_packet(packet):
    """
    Handle ARP (Address Resolution Protocol) packets.
    """
    arp = packet[ARP]
    lines = [
        "=" * 60,
        "ARP Packet Captured",
        "=" * 60,
        f"Source MAC       : {arp.hwsrc}",
        f"Destination MAC  : {arp.hwdst}",
        f"Source IP        : {arp.psrc}",
        f"Destination IP   : {arp.pdst}",
        f"Operation        : {'Request' if arp.op == 1 else 'Reply' if arp.op == 2 else 'Unknown'}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_ip_packet(packet):
    """
    Handle IPv4 packets without identified higher layer protocols.
    """
    ip = packet[IP]
    lines = [
        "=" * 60,
        "IPv4 Packet Captured",
        "=" * 60,
        f"Source IP        : {ip.src}",
        f"Destination IP   : {ip.dst}",
        f"Protocol Number  : {ip.proto}",
        f"TTL              : {ip.ttl}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_ipv6_packet(packet):
    """
    Handle IPv6 packets without identified higher layer protocols.
    """
    ipv6 = packet[IPv6]
    lines = [
        "=" * 60,
        "IPv6 Packet Captured",
        "=" * 60,
        f"Source IP        : {ipv6.src}",
        f"Destination IP   : {ipv6.dst}",
        f"Next Header      : {ipv6.nh}",
        f"Hop Limit        : {ipv6.hlim}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_tcp_packet(packet):
    """
    Handle TCP (Transmission Control Protocol) packets.
    """
    tcp = packet[TCP]
    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    ip_version = "IPv4" if packet.haslayer(IP) else "IPv6"
    
    lines = [
        "=" * 60,
        "TCP Packet Captured",
        "=" * 60,
        f"Source IP        : {ip_layer.src}",
        f"Destination IP   : {ip_layer.dst}",
        f"IP Version       : {ip_version}",
        f"Source Port      : {tcp.sport}",
        f"Destination Port : {tcp.dport}",
        f"Sequence Number  : {tcp.seq}",
        f"Acknowledgment   : {tcp.ack}",
        f"Flags            : {tcp.flags}",
        f"Window Size      : {tcp.window}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_udp_packet(packet):
    """
    Handle UDP (User Datagram Protocol) packets.
    """
    udp = packet[UDP]
    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    ip_version = "IPv4" if packet.haslayer(IP) else "IPv6"
    
    lines = [
        "=" * 60,
        "UDP Packet Captured",
        "=" * 60,
        f"Source IP        : {ip_layer.src}",
        f"Destination IP   : {ip_layer.dst}",
        f"IP Version       : {ip_version}",
        f"Source Port      : {udp.sport}",
        f"Destination Port : {udp.dport}",
        f"Length           : {udp.len}",
        f"Checksum         : {udp.chksum}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_dns_packet(packet):
    """
    Handle DNS (Domain Name System) packets.
    """
    dns = packet[DNS]
    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    ip_version = "IPv4" if packet.haslayer(IP) else "IPv6"
    
    # Extract DNS query/response type
    dns_type = "Response" if dns.qr else "Query"
    
    lines = [
        "=" * 60,
        "DNS Packet Captured",
        "=" * 60,
        f"Source IP        : {ip_layer.src}",
        f"Destination IP   : {ip_layer.dst}",
        f"IP Version       : {ip_version}",
        f"DNS Type         : {dns_type}",
        f"Transaction ID   : {dns.id}",
        f"Query Count      : {dns.qdcount}",
        f"Answer Count     : {dns.ancount}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_icmp_packet(packet):
    """
    Handle ICMP/ICMPv6 (Internet Control Message Protocol) packets.
    """
    icmp = packet[ICMP]
    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    ip_version = "IPv4" if packet.haslayer(IP) else "IPv6"
    icmp_version = "ICMP" if packet.haslayer(IP) else "ICMPv6"
    
    lines = [
        "=" * 60,
        f"{icmp_version} Packet Captured",
        "=" * 60,
        f"Source IP        : {ip_layer.src}",
        f"Destination IP   : {ip_layer.dst}",
        f"IP Version       : {ip_version}",
        f"Type             : {icmp.type}",
        f"Code             : {icmp.code}",
        f"Checksum         : {icmp.chksum}",
        f"Packet Length    : {len(packet)} Bytes",
        ""
    ]
    return lines


def _handle_unknown_packet(packet):
    """
    Handle unknown or unclassified packets.
    """
    lines = [
        "=" * 60,
        "Unknown Packet Captured",
        "=" * 60,
        f"Packet Type      : Unknown",
        f"Packet Length    : {len(packet)} Bytes",
        f"Packet Summary   : {packet.summary()}",
        ""
    ]
    return lines


def start_capture():
    """
    Starts packet sniffing and logs to file.
    """

    print("\n" + "=" * 60)
    print("MODULE 1 : PACKET MONITORING")
    print("=" * 60)

    print(f"Monitoring Interface : {INTERFACE}")
    print(f"Packet Limit         : {PACKET_LIMIT}")
    print(f"Log File             : {LOG_FILE}")

    print("\nWaiting for packets...\n")

    try:
        # Initialize database
        init_database()
        print("Database initialized.\n")
        
        # Open log file for writing
        with open(LOG_FILE, 'w') as log_file:
            # Write header to log file
            log_file.write("="*60 + "\n")
            log_file.write("PACKET CAPTURE LOG\n")
            log_file.write("="*60 + "\n")
            log_file.write(f"Monitoring Interface : {INTERFACE}\n")
            log_file.write(f"Packet Limit         : {PACKET_LIMIT}\n")
            log_file.write("="*60 + "\n\n")
            log_file.flush()
            
            sniff(
                iface=INTERFACE,
                prn=lambda pkt: packet_callback(pkt, log_file),
                count=PACKET_LIMIT,
                store=False
            )
        
        print("\nPacket Capture Completed.")
        print(f"Logs saved to: {LOG_FILE}")
        print(f"Database: {DB_FILE}")
    
    except RuntimeError as e:
        if "winpcap" in str(e).lower() or "not installed" in str(e).lower():
            print("\n" + "=" * 60)
            print("ERROR: Npcap/WinPcap is not installed!")
            print("=" * 60)
            print("\nNpcap is required for packet capture on Windows.")
            print("\nTo fix this:")
            print("1. Download Npcap from: https://nmap.org/npcap/")
            print("2. Install it with administrator privileges")
            print("3. Restart your computer")
            print("4. Run this script again")
            print("\nAlternatively, you can use Layer 3 (IP-level) sniffing by running:")
            print("  python packet_capture_l3.py")
            sys.exit(1)
        else:
            raise


if __name__ == "__main__":
    start_capture()