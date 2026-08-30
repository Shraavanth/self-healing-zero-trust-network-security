"""
database.py
-----------
SQLite database module for packet capture data

This module handles database operations for storing
captured network packets.
"""

import json
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

    # Create detections table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attack_type TEXT,
            source_ip TEXT,
            source_mac TEXT,
            domain TEXT,
            severity TEXT,
            confidence REAL,
            risk_score INTEGER,
            message TEXT
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

def insert_detection(detection_data):
    """
    Insert a detection record into the database.
    
    Args:
        detection_data (dict): Dictionary containing detection information
                           with keys: attack_type, source_ip, source_mac, domain,
                           severity, confidence, risk_score, message
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO detections (
            attack_type, source_ip, source_mac, domain,
            severity, confidence, risk_score,
            message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        detection_data.get("attack_type"),
        detection_data.get("source_ip"),
        detection_data.get("source_mac"),
        detection_data.get("domain"),
        detection_data.get("severity"),
        detection_data.get("confidence"),
        detection_data.get("risk_score"),
        detection_data.get("message")
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

def write_security_events_to_db(detection_result_json):
    """
    Import security events from JSON file into SQLite database.
    
    Args:
        detection_result_json (dict): JSON data containing security events
    """
     # Initialize database
    init_database()
    print("Database initialized.\n")
    
    # Check if the database file exists
    if not os.path.exists(DB_FILE):
        print(f"Database file '{DB_FILE}' does not exist. Please initialize the database first.")
        return
    
    # Parse the security events
    events = detection_result_json if isinstance(detection_result_json, list) else [detection_result_json]
    
    # Insert each event into the database
    for event in events:
        insert_detection(event)
        print(f"Inserted: {event.get('attack_type', 'INFO')} - {event.get('message')}")
    
    print(f"\nTotal events imported: {len(events)}")


# =====================================================
# DETECTION GET METHODS
# =====================================================

def get_detection_count():
    """
    Get the total number of detections stored in the database.
    
    Returns:
        int: Total detection count
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM detections")
    count = cursor.fetchone()[0]
    
    conn.close()
    return count


def get_all_detections():
    """
    Retrieve all detections from the database.
    
    Returns:
        list: List of detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM detections ORDER BY timestamp DESC")
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_type(attack_type):
    """
    Retrieve detections filtered by attack type.
    
    Args:
        attack_type (str): Attack type to filter by (e.g., 'POSSIBLE_ARP_SPOOFING', 
                          'POSSIBLE_DNS_SPOOFING', 'POSSIBLE_PHISHING')
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM detections WHERE attack_type = ? ORDER BY timestamp DESC",
        (attack_type,)
    )
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_severity(severity):
    """
    Retrieve detections filtered by severity level.
    
    Args:
        severity (str): Severity level to filter by ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM detections WHERE severity = ? ORDER BY timestamp DESC",
        (severity,)
    )
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_source_ip(source_ip):
    """
    Retrieve detections from a specific source IP address.
    
    Args:
        source_ip (str): Source IP address to search for
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM detections WHERE source_ip = ? ORDER BY timestamp DESC",
        (source_ip,)
    )
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_domain(domain):
    """
    Retrieve detections associated with a specific domain.
    
    Args:
        domain (str): Domain to search for
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM detections WHERE domain = ? ORDER BY timestamp DESC",
        (domain,)
    )
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_recent_detections(limit=10):
    """
    Retrieve the most recent detections.
    
    Args:
        limit (int): Maximum number of recent detections to return (default: 10)
    
    Returns:
        list: List of recent detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_confidence(min_confidence=0.0, max_confidence=1.0):
    """
    Retrieve detections filtered by confidence score range.
    
    Args:
        min_confidence (float): Minimum confidence score (0.0 to 1.0)
        max_confidence (float): Maximum confidence score (0.0 to 1.0)
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM detections 
        WHERE confidence >= ? AND confidence <= ?
        ORDER BY timestamp DESC
    """, (min_confidence, max_confidence))
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_by_risk_score(min_risk=0, max_risk=100):
    """
    Retrieve detections filtered by risk score range.
    
    Args:
        min_risk (int): Minimum risk score (0 to 100)
        max_risk (int): Maximum risk score (0 to 100)
    
    Returns:
        list: List of matching detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM detections 
        WHERE risk_score >= ? AND risk_score <= ?
        ORDER BY timestamp DESC
    """, (min_risk, max_risk))
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_high_risk_detections(risk_threshold=70):
    """
    Retrieve high-risk detections above a specified threshold.
    
    Args:
        risk_threshold (int): Minimum risk score threshold (default: 70)
    
    Returns:
        list: List of high-risk detection records as dictionaries
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM detections 
        WHERE risk_score >= ?
        ORDER BY risk_score DESC, timestamp DESC
    """, (risk_threshold,))
    detections = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return detections


def get_detections_summary():
    """
    Get a summary of detections grouped by attack type and severity.
    
    Returns:
        dict: Summary statistics with counts by type and severity
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Count by attack type
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM detections 
        WHERE attack_type IS NOT NULL
        GROUP BY attack_type
    """)
    by_type = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Count by severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM detections 
        GROUP BY severity
    """)
    by_severity = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Total count
    cursor.execute("SELECT COUNT(*) FROM detections")
    total = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total": total,
        "by_type": by_type,
        "by_severity": by_severity
    }


