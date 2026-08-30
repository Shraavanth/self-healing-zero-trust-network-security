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


# =====================================================
# PYTHON PATH
# =====================================================

sys.path.append(DETECTION_DIR)
sys.path.append(PACKET_MONITORING_DIR)


# =====================================================
# IMPORTS
# =====================================================

from scapy.all import (
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR
)

from feature_extractor import extract_features

from dns_spoof_detector import DNSSpoofDetector


# =====================================================
# CREATE DETECTOR
# =====================================================

detector = DNSSpoofDetector()


# =====================================================
# DNS PACKET 1
# FIRST OBSERVATION
# =====================================================

dns_packet_1 = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    IP(
        src="192.168.1.5",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=50000,
        dport=53
    )
    /
    DNS(
        id=1,
        qr=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A"
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            rdata="93.184.216.34",
            ttl=300
        )
    )
)


# =====================================================
# FEATURE EXTRACTION
# =====================================================

features_1 = extract_features(
    dns_packet_1
)


# =====================================================
# DNS DETECTION
# =====================================================

result_1 = detector.analyze(
    features_1
)


print("\n========== DNS PACKET 1 ==========")

print("\nExtracted DNS Features:")

for key, value in features_1.items():

    if (
        key.startswith("dns")
        or key.startswith("is_dns")
        or key in [
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol"
        ]
    ):

        print(
            f"{key:20}: {value}"
        )


print("\nDetection Result:")

print(result_1)


# =====================================================
# DNS PACKET 2
# SAME ANSWER
# =====================================================

dns_packet_2 = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    IP(
        src="192.168.1.5",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=50001,
        dport=53
    )
    /
    DNS(
        id=2,
        qr=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A"
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            rdata="93.184.216.34",
            ttl=300
        )
    )
)


features_2 = extract_features(
    dns_packet_2
)

result_2 = detector.analyze(
    features_2
)


print("\n========== DNS PACKET 2 ==========")

print("\nDetection Result:")

print(result_2)


# =====================================================
# DNS PACKET 3
# DIFFERENT ANSWER
# =====================================================

dns_packet_3 = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    IP(
        src="192.168.1.5",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=50002,
        dport=53
    )
    /
    DNS(
        id=3,
        qr=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A"
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            rdata="5.6.7.8",
            ttl=300
        )
    )
)


features_3 = extract_features(
    dns_packet_3
)

result_3 = detector.analyze(
    features_3
)


print("\n========== DNS PACKET 3 ==========")

print("\nExtracted DNS Features:")

for key, value in features_3.items():

    if key.startswith("dns"):

        print(
            f"{key:20}: {value}"
        )


print("\nDetection Result:")

print(result_3)