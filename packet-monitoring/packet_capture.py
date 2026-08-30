"""
packet_capture.py
-----------------
Module 1 - Real-Time Security Monitoring

Captures live network packets using Scapy,
extracts security features, sends them to the
unified Detection Engine, logs security events,
and maintains security statistics.

Author : Shraavanth
"""

import os
import sys

from scapy.all import sniff, IP, ARP, DNS

from config import INTERFACE, PACKET_LIMIT


# =====================================================
# PROJECT PATH SETUP
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)

DETECTION_DIR = os.path.join(
    PROJECT_ROOT,
    "phishing-spoofing-detection"
)

if DETECTION_DIR not in sys.path:
    sys.path.append(DETECTION_DIR)


# =====================================================
# IMPORT PROJECT MODULES
# =====================================================

from feature_extractor import extract_features
from detection_engine import DetectionEngine
from event_logger import EventLogger
from security_statistics import SecurityStatistics
from database import write_security_events_to_db, init_database

# =====================================================
# CREATE DETECTION ENGINE
# =====================================================

detection_engine = DetectionEngine()


# =====================================================
# CREATE EVENT LOGGER
# =====================================================

event_logger = EventLogger()


# =====================================================
# CREATE SECURITY STATISTICS
# =====================================================

security_statistics = SecurityStatistics()


# =====================================================
# DISPLAY SECURITY EVENT
# =====================================================

def display_detection_event(event):
    """
    Display a unified security detection event.

    INFO events are displayed as informational events.
    Actual detections are displayed as security alerts.
    """

    if event is None:
        return

    result = event.to_dict()

    # =================================================
    # INFORMATION EVENT
    # =================================================

    if result["severity"] == "INFO":

        print("\n" + "-" * 60)
        print("INFORMATION EVENT")
        print("-" * 60)

        print(
            f"Severity         : "
            f"{result['severity']}"
        )

        print(
            f"Message          : "
            f"{result['message']}"
        )

        if result["source_ip"] is not None:

            print(
                f"Source IP        : "
                f"{result['source_ip']}"
            )

        if result["source_mac"] is not None:

            print(
                f"Source MAC       : "
                f"{result['source_mac']}"
            )

        if result["domain"] is not None:

            print(
                f"Domain           : "
                f"{result['domain']}"
            )

        print("-" * 60)

        return

    # =================================================
    # SECURITY ALERT
    # =================================================

    print("\n" + "!" * 60)
    print("SECURITY ALERT")
    print("!" * 60)

    print(
        f"Attack Type      : "
        f"{result['attack_type']}"
    )

    print(
        f"Severity         : "
        f"{result['severity']}"
    )

    print(
        f"Confidence       : "
        f"{result['confidence']}"
    )

    print(
        f"Risk Score       : "
        f"{result['risk_score']}"
    )

    if result["source_ip"] is not None:

        print(
            f"Source IP        : "
            f"{result['source_ip']}"
        )

    if result["source_mac"] is not None:

        print(
            f"Source MAC       : "
            f"{result['source_mac']}"
        )

    if result["domain"] is not None:

        print(
            f"Domain           : "
            f"{result['domain']}"
        )

    print(
        f"Message          : "
        f"{result['message']}"
    )

    print("!" * 60)


# =====================================================
# ARP PACKET DISPLAY
# =====================================================

def analyze_arp(features):
    """
    Display important ARP information.
    """

    print("\n" + "-" * 60)
    print("ARP TRAFFIC")
    print("-" * 60)

    print(
        f"Operation        : "
        f"{features['arp_operation']}"
    )

    print(
        f"Source IP        : "
        f"{features['arp_src_ip']}"
    )

    print(
        f"Source MAC       : "
        f"{features['arp_src_mac']}"
    )

    print(
        f"Destination IP   : "
        f"{features['arp_dst_ip']}"
    )

    print(
        f"Destination MAC  : "
        f"{features['arp_dst_mac']}"
    )


# =====================================================
# DNS PACKET DISPLAY
# =====================================================

def analyze_dns(features):
    """
    Display important DNS information.
    """

    print("\n" + "-" * 60)
    print("DNS TRAFFIC")
    print("-" * 60)

    print(
        f"Query            : "
        f"{features['dns_query']}"
    )

    print(
        f"Query Type       : "
        f"{features['dns_query_type']}"
    )

    print(
        f"Answers          : "
        f"{features['dns_answers']}"
    )

    print(
        f"Source IP        : "
        f"{features['src_ip']}"
    )

    print(
        f"Destination IP   : "
        f"{features['dst_ip']}"
    )

    print(
        f"Source Port      : "
        f"{features['src_port']}"
    )

    print(
        f"Destination Port : "
        f"{features['dst_port']}"
    )


# =====================================================
# NORMAL IPv4 PACKET DISPLAY
# =====================================================

def analyze_normal_packet(features):
    """
    Display compact information for normal traffic.
    """

    print(
        f"[NORMAL TRAFFIC] "
        f"{features['src_ip']} -> "
        f"{features['dst_ip']} | "
        f"{features['protocol']} | "
        f"{features['packet_length']} Bytes"
    )


# =====================================================
# PACKET CALLBACK
# =====================================================

def packet_callback(packet):
    """
    Called automatically by Scapy for every
    captured packet.
    """

    # =================================================
    # STEP 1 - RECORD PACKET
    # =================================================

    security_statistics.record_packet()


    # =================================================
    # STEP 2 - EXTRACT FEATURES
    # =================================================

    try:

        features = extract_features(packet)

    except Exception as error:

        print("\n[ERROR] Feature extraction failed")

        print(
            f"Error : {error}"
        )

        return


    # =================================================
    # STEP 3 - DETECTION ENGINE
    # =================================================

    try:

        detection_result = (
            detection_engine.analyze_packet(
                features
            )
        )

    except Exception as error:

        print("\n[ERROR] Detection engine failed")

        print(
            f"Error : {error}"
        )

        detection_result = None


    # =================================================
    # STEP 4 - DISPLAY PACKET
    # =================================================

    # -------------------------------------------------
    # ARP
    # -------------------------------------------------

    if packet.haslayer(ARP):

        analyze_arp(features)


    # -------------------------------------------------
    # DNS
    # -------------------------------------------------

    elif packet.haslayer(DNS):

        analyze_dns(features)


    # -------------------------------------------------
    # IPv4
    # -------------------------------------------------

    elif packet.haslayer(IP):

        analyze_normal_packet(
            features
        )


    # =================================================
    # STEP 5 - PROCESS SECURITY EVENT
    # =================================================

    if detection_result is not None:

        # ---------------------------------------------
        # Record statistics
        # ---------------------------------------------

        security_statistics.record_event(
            detection_result
        )


        # ---------------------------------------------
        # Display event
        # ---------------------------------------------

        display_detection_event(
            detection_result
        )


        # ---------------------------------------------
        # Save event to JSON
        # ---------------------------------------------

        try:

            event_logger.log_event(
                detection_result
            )

            print("[LOGGED] Security event saved")
           
            write_security_events_to_db(detection_result.to_dict())
            print("[DB] Security event saved into database")

        except Exception as error:

            print("[ERROR] Event logging failed")

            print(f"Error : {error}")


# =====================================================
# START PACKET CAPTURE
# =====================================================

def start_capture():
    """
    Start live network packet sniffing.
    """

    print("\n" + "=" * 60)
    print("MODULE 1 : REAL-TIME SECURITY MONITORING")
    print("=" * 60)

    print(
        f"Monitoring Interface : "
        f"{INTERFACE}"
    )

    print(
        f"Packet Limit         : "
        f"{PACKET_LIMIT}"
    )

    print(
        f"Event Log            : "
        f"{event_logger.log_file}"
    )

    print("=" * 60)

    print(
        "\nMonitoring started..."
    )

    print(
        "Normal traffic will be shown compactly."
    )

    print(
        "Information events will be shown separately."
    )

    print(
        "Security alerts will be highlighted."
    )

    print(
        "\nPress Ctrl+C to stop.\n"
    )


    # =================================================
    # START SCAPY
    # =================================================

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            count=PACKET_LIMIT,
            store=False
        )

    except KeyboardInterrupt:

        print(
            "\n\nCapture stopped by user."
        )

    except Exception as error:

        print(
            "\n[ERROR] Packet capture failed"
        )

        print(
            f"Error : {error}"
        )

        return


    # =================================================
    # SECURITY SUMMARY
    # =================================================

    security_statistics.display_summary()


    # =================================================
    # FINAL INFORMATION
    # =================================================

    print(
        f"\nSecurity Log File : "
        f"{event_logger.log_file}"
    )

    print(
        "\nPacket Capture Completed."
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    start_capture()

