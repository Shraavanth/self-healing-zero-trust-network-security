import sys
import os
import json


# =====================================================
# PROJECT PATH
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DETECTION_DIR = os.path.dirname(
    CURRENT_DIR
)

sys.path.append(DETECTION_DIR)


from arp_spoof_detector import ARPSpoofDetector


# =====================================================
# CREATE DETECTOR
# =====================================================

detector = ARPSpoofDetector()


# =====================================================
# TEST 1
# FIRST IP-MAC MAPPING
# =====================================================

features_1 = {
    "is_arp": True,
    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "AA:AA:AA:AA:AA:AA",
    "arp_operation": 2
}

result_1 = detector.analyze(features_1)

print("\n========== TEST 1 ==========")
print(json.dumps(result_1, indent=2))


# =====================================================
# TEST 2
# SAME IP + SAME MAC
# =====================================================

features_2 = {
    "is_arp": True,
    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "AA:AA:AA:AA:AA:AA",
    "arp_operation": 2
}

result_2 = detector.analyze(features_2)

print("\n========== TEST 2 ==========")
print(json.dumps(result_2, indent=2))


# =====================================================
# TEST 3
# FIRST MAC CHANGE
# =====================================================

features_3 = {
    "is_arp": True,
    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "CC:CC:CC:CC:CC:CC",
    "arp_operation": 2
}

result_3 = detector.analyze(features_3)

print("\n========== TEST 3 ==========")
print(result_3)


# =====================================================
# TEST 4
# SECOND MAC CHANGE
# =====================================================

features_4 = {
    "is_arp": True,
    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "DD:DD:DD:DD:DD:DD",
    "arp_operation": 2
}

result_4 = detector.analyze(features_4)

print("\n========== TEST 4 ==========")
print(result_4)


# =====================================================
# CURRENT TABLE
# =====================================================

print("\n========== CURRENT IP-MAC TABLE ==========")

table = detector.get_ip_mac_table()

for ip, information in table.items():

    print(f"\nIP Address: {ip}")

    for key, value in information.items():
        print(f"{key:15}: {value}")
