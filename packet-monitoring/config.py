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
PACKET_LIMIT = 10

# Log file configuration
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, f"packet_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)