"""
test_security_statistics.py
---------------------------
Tests the Security Statistics module.

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
# IMPORT
# =====================================================

from detection_event import DetectionEvent

from security_statistics import SecurityStatistics


# =====================================================
# TEST START
# =====================================================

print("\n" + "=" * 60)
print("SECURITY STATISTICS TEST")
print("=" * 60)


# =====================================================
# CREATE STATISTICS OBJECT
# =====================================================

stats = SecurityStatistics()


# =====================================================
# TEST PACKETS
# =====================================================

print("\n========== RECORDING PACKETS ==========")

for _ in range(10):

    stats.record_packet()

print(
    "10 packets recorded."
)


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

stats.record_event(
    arp_event
)

print(
    "ARP event recorded."
)


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

stats.record_event(
    dns_event
)

print(
    "DNS event recorded."
)


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

stats.record_event(
    phishing_event
)

print(
    "Phishing event recorded."
)


# =====================================================
# TEST 4 - INFO EVENT
# =====================================================

print("\n========== TEST 4 : INFO EVENT ==========")

info_event = DetectionEvent(

    attack_type=None,

    source_ip="192.168.1.10",

    source_mac="AA:AA:AA:AA:AA:AA",

    severity="INFO",

    confidence=0.0,

    risk_score=0,

    message="New IP-MAC mapping observed"
)

stats.record_event(
    info_event
)

print(
    "INFO event recorded."
)


# =====================================================
# DISPLAY STATISTICS
# =====================================================

stats.display_summary()


# =====================================================
# VERIFY VALUES
# =====================================================

print("\n========== VERIFICATION ==========")

result = stats.get_statistics()

print(
    "Total Packets :",
    result["total_packets"]
)

print(
    "Total Events  :",
    result["total_events"]
)

print(
    "ARP Events    :",
    result["arp_spoofing_events"]
)

print(
    "DNS Events    :",
    result["dns_spoofing_events"]
)

print(
    "Phishing      :",
    result["phishing_events"]
)

print(
    "HIGH          :",
    result["high_events"]
)

print(
    "MEDIUM        :",
    result["medium_events"]
)

print(
    "INFO          :",
    result["info_events"]
)


# =====================================================
# AUTOMATIC ASSERTIONS
# =====================================================

assert result["total_packets"] == 10

assert result["total_events"] == 4

assert result["arp_spoofing_events"] == 1

assert result["dns_spoofing_events"] == 1

assert result["phishing_events"] == 1

assert result["high_events"] == 1

assert result["medium_events"] == 2

assert result["info_events"] == 1


print("\n==============================================")
print("ALL SECURITY STATISTICS TESTS PASSED")
print("==============================================")