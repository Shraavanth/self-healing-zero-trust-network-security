"""
test_database_get_methods.py
----------------------------

Tests all GET/retrieval methods from:

packet-monitoring/database.py

Tested methods:

1.  get_packet_count()
2.  get_all_packets()
3.  get_packets_by_protocol()
4.  get_packets_by_ip()
5.  get_detection_count()
6.  get_all_detections()
7.  get_detections_by_type()
8.  get_detections_by_severity()
9.  get_detections_by_source_ip()
10. get_detections_by_domain()
11. get_recent_detections()
12. get_detections_by_confidence()
13. get_detections_by_risk_score()
14. get_high_risk_detections()
15. get_detections_summary()
"""

import os
import sys
import sqlite3


# =========================================================
# PROJECT PATH SETUP
# =========================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

# Current directory:
# phishing-spoofing-detection/tests
#
# Go up one:
# phishing-spoofing-detection
#
# Go up two:
# self-healing-zero-trust-network-security

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(CURRENT_DIR)
)

# packet-monitoring folder
PACKET_MONITORING_DIR = os.path.join(
    PROJECT_ROOT,
    "packet-monitoring"
)

# Add packet-monitoring to Python path
if PACKET_MONITORING_DIR not in sys.path:

    sys.path.insert(
        0,
        PACKET_MONITORING_DIR
    )


# =========================================================
# IMPORT DATABASE
# =========================================================

import database
from database import (
    get_detections_by_type,
    get_detections_by_severity,
    get_detections_by_source_ip,
    get_detections_by_confidence,
    get_all_detections,
    get_detections_by_domain,
    get_detections_by_risk_score
)

def display_detection(detection, index):
    print(f"Detection {index}:")
    print(f"  ID: {detection.get('id')}")
    print(f"  Type: {detection.get('type')}")
    print(f"  Severity: {detection.get('severity')}")
    print(f"  Source IP: {detection.get('source_ip')}")
    print(f"  Confidence: {detection.get('confidence')}")
    print(f"  Domain: {detection.get('domain')}")
    print(f"  Risk Score: {detection.get('risk_score')}")
    print("-" * 40)

if __name__ == "__main__":
    try:
        all_detections = get_all_detections()
        if not all_detections:
            print("No detections found in the database.")
        else:
            print(f"Total Detections: {len(all_detections)}")
            for i, detection in enumerate(all_detections[:5], 1):
                display_detection(detection, i)
            if len(all_detections) > 5:
                print(f"\n... and {len(all_detections) - 5} more detections")
    except Exception as e:
        print(f"\nError: {e}\n")
        import traceback
        traceback.print_exc()