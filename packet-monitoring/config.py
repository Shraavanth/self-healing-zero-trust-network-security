"""
config.py
----------
Configuration file for Module 1: Packet Monitoring
"""

import os
from datetime import datetime

# Network interface to monitor (Windows Npcap interface)
INTERFACE = r"\Device\NPF_{F882A092-49BF-4F87-B4CB-71721F92148D}"

# Number of packets to capture before stopping
PACKET_LIMIT = 100
