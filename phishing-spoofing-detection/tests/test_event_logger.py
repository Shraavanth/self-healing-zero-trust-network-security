"""
test_event_logger.py
--------------------
Tests the Security Event Logger.

Author : Shraavanth
"""

import os
import sys


# =====================================================
# PROJECT PATH
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DETECTION_DIR = os.path.dirname(
    CURRENT_DIR
)

if DETECTION_DIR not in sys.path:

    sys.path.append(
        DETECTION_DIR
    )


# =====================================================
# IMPORTS
# =====================================================

from detection_event import DetectionEvent

from event_logger import EventLogger


# =====================================================
# TEST START
# =====================================================

print("\n==============================================")
print("EVENT LOGGER TEST")
print("==============================================")


# =====================================================
# CREATE LOGGER
# =====================================================

logger = EventLogger()


# =====================================================
# CLEAR OLD TEST DATA
# =====================================================

logger.clear_log()


# =====================================================
# TEST 1 - ARP EVENT
# =====================================================

print("\n========== TEST 1 : ARP EVENT ==========")

arp_event = DetectionEvent(

    attack_type="POSSIBLE_ARP_SPOOFING",

    source_ip="192.168.1.1",

    source_mac="CC:CC:CC:CC:CC:CC",

    severity="HIGH",

    confidence=0.75,

    risk_score=75,

    message="IP-MAC mapping changed"
)


logger.log_event(
    arp_event
)

print("ARP event logged successfully.")


# =====================================================
# TEST 2 - DNS EVENT
# =====================================================

print("\n========== TEST 2 : DNS EVENT ==========")

dns_event = DetectionEvent(

    attack_type="POSSIBLE_DNS_SPOOFING",

    source_ip="192.168.1.5",

    domain="example.com",

    severity="MEDIUM",

    confidence=0.70,

    risk_score=70,

    message="DNS answer mapping changed"
)


logger.log_event(
    dns_event
)

print("DNS event logged successfully.")


# =====================================================
# TEST 3 - PHISHING EVENT
# =====================================================

print("\n========== TEST 3 : PHISHING EVENT ==========")

phishing_event = DetectionEvent(

    attack_type="POSSIBLE_PHISHING",

    domain="secure-paypal-login.com",

    severity="MEDIUM",

    confidence=0.40,

    risk_score=40,

    message="Suspicious domain characteristics detected"
)


logger.log_event(
    phishing_event
)

print("Phishing event logged successfully.")


# =====================================================
# TEST 4 - READ EVENTS
# =====================================================

print("\n========== TEST 4 : READ LOG ==========")

events = logger.get_events()

print(
    "Total Events :",
    len(events)
)


for index, event in enumerate(
    events,
    start=1
):

    print(
        f"\nEvent {index}:"
    )

    print(
        event
    )


# =====================================================
# LOG FILE LOCATION
# =====================================================

print("\n==============================================")
print("LOG FILE")
print("==============================================")

print(
    "Location :",
    logger.log_file
)

print(
    "\nEvent logging test completed."
)