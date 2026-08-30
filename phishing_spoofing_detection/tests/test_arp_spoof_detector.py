import sys
import os
import json

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from phishing_spoofing_detection.arp_spoof_detector import ARPSpoofDetector

detector = ARPSpoofDetector()


# =====================================================
# TEST 1: FIRST ARP OBSERVATION
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
# TEST 2: SAME IP + SAME MAC
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
# TEST 3: SAME IP + DIFFERENT MAC
# =====================================================

features_3 = {
    "is_arp": True,
    "arp_src_ip": "192.168.1.1",
    "arp_src_mac": "CC:CC:CC:CC:CC:CC",
    "arp_operation": 2
}

result_3 = detector.analyze(features_3)

print("\n========== TEST 3 ==========")
print(json.dumps(result_3, indent=2))