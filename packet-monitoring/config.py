"""
config.py
----------
Configuration file for Module 1: Packet Monitoring
"""

# Network interface to monitor (Windows Npcap interface)
INTERFACE = r"\Device\NPF_{4C2BE8EE-97F9-4348-ABE6-A83981DDBA35}"

# Number of packets to capture before stopping
PACKET_LIMIT = 100