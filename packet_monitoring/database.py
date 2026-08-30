"""
database.py
-----------
SQLite database module for packet capture data

This module handles database operations for storing
captured network packets.
"""

import sqlite3
import os
from datetime import datetime


# Database file path
DB_DIR = os.path.join(os.path.dirname(__file__), "db")
DB_FILE = os.path.join(DB_DIR, "packet_capture.db")

# Ensure database directory exists
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)


def init_database():
    """
    Initialize the database with required tables.
    Creates the packets table if it doesn't exist.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create packets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            packet_length INTEGER,
            arp_src_ip TEXT,
            arp_src_mac TEXT,
            arp_dst_ip TEXT,
            arp_dst_mac TEXT
        )
    """)
    
    conn.commit()
    conn.close()


def insert_packet(packet_data):
    """
    Insert a packet record into the database.
    
    Args:
        packet_data (dict): Dictionary containing packet information
                           with keys: src_mac, dst_mac, src_ip, dst_ip,
                           protocol, src_port, dst_port, packet_length,
                           arp_src_ip, arp_src_mac, arp_dst_ip, arp_dst_mac
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO packets (
            src_mac, dst_mac, src_ip, dst_ip, protocol,
            src_port, dst_port, packet_length,
            arp_src_ip, arp_src_mac, arp_dst_ip, arp_dst_mac
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_data.get("src_mac"),
        packet_data.get("dst_mac"),
        packet_data.get("src_ip"),
        packet_data.get("dst_ip"),
        packet_data.get("protocol"),
        packet_data.get("src_port"),
        packet_data.get("dst_port"),
        packet_data.get("packet_length"),
        packet_data.get("arp_src_ip"),
        packet_data.get("arp_src_mac"),
        packet_data.get("arp_dst_ip"),
        packet_data.get("arp_dst_mac")
    ))
    
    conn.commit()
    conn.close()


def get_packet_count():
    """
    Get the total number of packets stored in the database.
    
    Returns:
        int: Total packet count
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM packets")
    count = cursor.fetchone()[0]
    
    conn.close()
    return count


def get_all_packets():
    """
    Retrieve all packets from the database.
    
    Returns:
        list: List of packet records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC")
    packets = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return packets


def get_packets_by_protocol(protocol):
    """
    Retrieve packets filtered by protocol.
    
    Args:
        protocol (str): Protocol to filter by (e.g., 'TCP', 'UDP', 'ARP')
    
    Returns:
        list: List of matching packet records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM packets WHERE protocol = ? ORDER BY timestamp DESC",
        (protocol,)
    )
    packets = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return packets


def get_packets_by_ip(ip_address):
    """
    Retrieve packets involving a specific IP address.
    
    Args:
        ip_address (str): IP address to search for
    
    Returns:
        list: List of matching packet records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM packets 
        WHERE src_ip = ? OR dst_ip = ? OR arp_src_ip = ? OR arp_dst_ip = ?
        ORDER BY timestamp DESC
    """, (ip_address, ip_address, ip_address, ip_address))
    packets = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return packets
