"""
test_detection_engine.py
------------------------
Tests the unified DetectionEngine.

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

from detection_engine import DetectionEngine


# =====================================================
# CREATE ENGINE
# =====================================================

engine = DetectionEngine()


print("\n==============================================")
print("DETECTION ENGINE TEST")
print("==============================================")


# =====================================================
# TEST 1 - NORMAL PACKET
# =====================================================

print("\n========== TEST 1 : NORMAL ==========")

features = {
    "is_arp": False,
    "is_dns": False,
    "dns_query": None
}

result = engine.analyze_packet(
    features
)

print("Result :", result)


# =====================================================
# TEST 2 - PHISHING
# =====================================================

print("\n========== TEST 2 : PHISHING ==========")

features = {
    "is_arp": False,
    "is_dns": True,
    "dns_query": "secure-paypal-login.com"
}

result = engine.analyze_packet(
    features
)

print("Result :", result)


# =====================================================
# TEST 3 - ARP NORMAL
# =====================================================

print("\n========== TEST 3 : NORMAL ARP ==========")

arp_features = {
    "is_arp": True,
    "is_dns": False,
    "dns_query": None,

    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "AA:AA:AA:AA:AA:AA",
    "arp_operation": 2,

    "timestamp": "2026-08-29T10:00:00"
}

result = engine.analyze_packet(
    arp_features
)

print("Result :", result)


# =====================================================
# TEST 4 - ARP SPOOFING
# =====================================================

print("\n========== TEST 4 : ARP SPOOFING ==========")

arp_features = {
    "is_arp": True,
    "is_dns": False,
    "dns_query": None,

    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "CC:CC:CC:CC:CC:CC",
    "arp_operation": 2,

    "timestamp": "2026-08-29T10:01:00"
}

result = engine.analyze_packet(
    arp_features
)

print("Result :", result)


# =====================================================
# TEST 5 - ANOTHER ARP MAC CHANGE
# =====================================================

print("\n========== TEST 5 : REPEATED ARP SPOOFING ==========")

arp_features = {
    "is_arp": True,
    "is_dns": False,
    "dns_query": None,

    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "DD:DD:DD:DD:DD:DD",
    "arp_operation": 2,

    "timestamp": "2026-08-29T10:02:00"
}

result = engine.analyze_packet(
    arp_features
)

print("Result :", result)

# =====================================================
# TEST 6 - NORMAL DNS
# =====================================================

print("\n========== TEST 6 : NORMAL DNS ==========")

dns_features = {
    "is_arp": False,
    "is_dns": True,

    "dns_query": "example.com",
    "dns_query_type": "A",
    "dns_answers": ["93.184.216.34"],

    "src_ip": "192.168.1.5",
    "dst_ip": "8.8.8.8",
    "src_port": 50000,
    "dst_port": 53,

    "timestamp": "2026-08-29T10:03:00"
}

result = engine.analyze_packet(
    dns_features
)

print("Result :", result)


# =====================================================
# TEST 7 - DNS SPOOFING
# =====================================================

print("\n========== TEST 7 : DNS SPOOFING ==========")

dns_features = {
    "is_arp": False,
    "is_dns": True,

    "dns_query": "example.com",
    "dns_query_type": "A",
    "dns_answers": ["5.6.7.8"],

    "src_ip": "192.168.1.5",
    "dst_ip": "8.8.8.8",
    "src_port": 50000,
    "dst_port": 53,

    "timestamp": "2026-08-29T10:04:00"
}

result = engine.analyze_packet(
    dns_features
)

print("Result :", result)