"""
packet_capture.py
-----------------
Module 1 - Packet Monitoring

This program captures live network packets using Scapy and
displays basic packet information.

Author : Shraavanth
"""

from scapy.all import sniff, IP
from config import INTERFACE, PACKET_LIMIT


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
    Starts packet sniffing.
    """

    print("\n" + "=" * 60)
    print("MODULE 1 : PACKET MONITORING")
    print("=" * 60)

    print(f"Monitoring Interface : {INTERFACE}")
    print(f"Packet Limit         : {PACKET_LIMIT}")

    print("\nWaiting for packets...\n")

    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        count=PACKET_LIMIT,
        store=False
    )

    print("\nPacket Capture Completed.")


if __name__ == "__main__":
    start_capture()