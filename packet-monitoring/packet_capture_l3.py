"""
packet_capture_l3.py
--------------------
Module 1 - Packet Monitoring (Layer 3 - No Npcap Required)

This program captures live network packets at Layer 3 (IP layer) using Scapy.
Unlike packet_capture.py, this doesn't require Npcap to be installed.
It displays basic packet information for IP packets.

Author : Shraavanth
Modified for L3 compatibility
"""

from scapy.all import sniff, IP, conf
from config import PACKET_LIMIT


def packet_callback(packet):
    """
    This function is automatically called by Scapy
    whenever a packet is captured.
    """

    # Check whether the packet contains an IP layer
    if packet.haslayer(IP):

        print("=" * 60)
        print("Packet Captured")
        print("=" * 60)

        print(f"Source IP        : {packet[IP].src}")
        print(f"Destination IP   : {packet[IP].dst}")
        print(f"Protocol Number  : {packet[IP].proto}")
        print(f"Packet Length    : {len(packet)} Bytes")

        print()


def start_capture():
    """
    Starts packet sniffing at Layer 3 (IP layer).
    This method uses L3socket and doesn't require Npcap.
    """

    print("\n" + "=" * 60)
    print("MODULE 1 : PACKET MONITORING (Layer 3 - L3socket)")
    print("=" * 60)

    # Use L3socket instead of raw socket
    print(f"Packet Limit         : {PACKET_LIMIT}")
    print("Note: Using Layer 3 socket (no Npcap required)")

    print("\nWaiting for packets...\n")

    try:
        # Configure to use L3socket
        conf.L3socket = conf.L3socket or None
        
        # Use L3socket for Layer 3 sniffing without Npcap
        sniff(
            prn=packet_callback,
            count=PACKET_LIMIT,
            store=False,
            filter="ip"  # Only capture IP packets
        )
        print("\nPacket Capture Completed.")
    
    except Exception as e:
        print(f"\nError during packet capture: {e}")
        print("\nTroubleshooting:")
        print("- Ensure you have network connectivity")
        print("- Run the script with administrator privileges")
        print("- Check your network configuration")
        print("\nNote: For full packet capture without administrator restrictions,")
        print("install Npcap from: https://nmap.org/npcap/")
        import sys
        sys.exit(1)


if __name__ == "__main__":
    start_capture()
