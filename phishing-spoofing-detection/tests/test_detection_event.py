"""
test_detection_event.py
-----------------------
Tests the unified DetectionEvent class.

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
    sys.path.append(DETECTION_DIR)


# =====================================================
# IMPORT
# =====================================================

from detection_event import DetectionEvent


# =====================================================
# TEST 1
# =====================================================

print("\n==============================================")
print("DETECTION EVENT TEST")
print("==============================================")


print("\n========== TEST 1 : ARP EVENT ==========")

event = DetectionEvent(
    attack_type="POSSIBLE_ARP_SPOOFING",
    source_ip="192.168.1.1",
    source_mac="CC:CC:CC:CC:CC:CC",
    severity="HIGH",
    confidence=0.85,
    risk_score=85,
    message="IP-MAC mapping changed"
)

print(event.to_dict())


# =====================================================
# TEST 2
# =====================================================

print("\n========== TEST 2 : DNS EVENT ==========")

event = DetectionEvent(
    attack_type="POSSIBLE_DNS_SPOOFING",
    source_ip="192.168.1.5",
    domain="example.com",
    severity="MEDIUM",
    confidence=0.70,
    risk_score=70,
    message="DNS answer mapping changed"
)

print(event.to_dict())


# =====================================================
# TEST 3
# =====================================================

print("\n========== TEST 3 : PHISHING EVENT ==========")

event = DetectionEvent(
    attack_type="POSSIBLE_PHISHING",
    domain="secure-paypal-login.com",
    severity="MEDIUM",
    confidence=0.40,
    risk_score=40,
    message="Suspicious domain characteristics detected"
)

print(event.to_dict())