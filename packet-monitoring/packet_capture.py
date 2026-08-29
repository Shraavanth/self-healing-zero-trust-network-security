"""
packet_capture.py
-----------------
Module 1 - Packet Monitoring

This program captures live network packets using Scapy and
displays basic packet information.

Author : Shraavanth
"""

from scapy.all import sniff, IP, conf
from config import INTERFACE, PACKET_LIMIT, LOG_FILE
from database import init_database, insert_packet, DB_FILE
from packet_parser import parse_packet
import sys


def packet_callback(packet, log_file_handle):
    """
    This function is automatically called by Scapy
    whenever a packet is captured. Logs packet info to console,
    log file, and database.
    """

    # Check whether the packet contains an IP layer
    if packet.haslayer(IP):
        # Parse packet data
        packet_data = parse_packet(packet)
        
        output_lines = [
            "=" * 60,
            "Packet Captured",
            "=" * 60,
            f"Source IP        : {packet[IP].src}",
            f"Destination IP   : {packet[IP].dst}",
            f"Protocol Number  : {packet[IP].proto}",
            f"Packet Length    : {len(packet)} Bytes",
            ""
        ]
        
        # Print to console
        for line in output_lines:
            print(line)
        
        # Write to log file
        for line in output_lines:
            log_file_handle.write(line + "\n")
        log_file_handle.flush()  # Ensure data is written immediately
        
        # Insert into database
        try:
            insert_packet(packet_data)
        except Exception as e:
            print(f"Error inserting packet into database: {e}")


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