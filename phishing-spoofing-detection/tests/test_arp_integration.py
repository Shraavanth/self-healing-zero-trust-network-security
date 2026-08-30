import sys
import os


# =====================================================
# PROJECT PATHS
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DETECTION_DIR = os.path.dirname(
    CURRENT_DIR
)

PROJECT_ROOT = os.path.dirname(
    DETECTION_DIR
)

PACKET_MONITORING_DIR = os.path.join(
    PROJECT_ROOT,
    "packet-monitoring"
)


# Add project directories to Python path
sys.path.append(DETECTION_DIR)
sys.path.append(PACKET_MONITORING_DIR)


# =====================================================
# IMPORTS
# =====================================================

from scapy.all import Ether, ARP

from feature_extractor import extract_features
from arp_spoof_detector import ARPSpoofDetector


# =====================================================
# CREATE DETECTOR
# =====================================================

detector = ARPSpoofDetector()


# =====================================================
# PACKET 1
# FIRST OBSERVATION
# =====================================================

arp_packet_1 = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    ARP(
        op=2,
        hwsrc="AA:AA:AA:AA:AA:AA",
        psrc="192.168.1.1",
        hwdst="BB:BB:BB:BB:BB:BB",
        pdst="192.168.1.10"
    )
)

features_1 = extract_features(arp_packet_1)
result_1 = detector.analyze(features_1)

print("\n========== PACKET 1 ==========")

print("\nExtracted Features:")
print(features_1)

print("\nDetection Result:")
print(result_1)


# =====================================================
# PACKET 2
# SAME IP + SAME MAC
# =====================================================

arp_packet_2 = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    ARP(
        op=2,
        hwsrc="AA:AA:AA:AA:AA:AA",
        psrc="192.168.1.1",
        hwdst="BB:BB:BB:BB:BB:BB",
        pdst="192.168.1.10"
    )
)

features_2 = extract_features(arp_packet_2)
result_2 = detector.analyze(features_2)

print("\n========== PACKET 2 ==========")

print("\nExtracted Features:")
print(features_2)

print("\nDetection Result:")
print(result_2)


# =====================================================
# PACKET 3
# SAME IP + DIFFERENT MAC
# =====================================================

arp_packet_3 = (
    Ether(
        src="CC:CC:CC:CC:CC:CC",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    ARP(
        op=2,
        hwsrc="CC:CC:CC:CC:CC:CC",
        psrc="192.168.1.1",
        hwdst="BB:BB:BB:BB:BB:BB",
        pdst="192.168.1.10"
    )
)

features_3 = extract_features(arp_packet_3)
result_3 = detector.analyze(features_3)

print("\n========== PACKET 3 ==========")

print("\nExtracted Features:")
print(features_3)

print("\nDetection Result:")
print(result_3)