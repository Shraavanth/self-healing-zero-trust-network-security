"""
test_end_to_end.py
------------------
End-to-End Integration Test

Tests:

1. Phishing Detection
2. ARP Spoofing Detection
3. DNS Spoofing Detection
4. Detection Event Creation
5. Event Logging
6. Security Statistics

Author : Shraavanth
"""

import os
import sys


# =====================================================
# PROJECT PATH SETUP
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
# IMPORT MODULES
# =====================================================

from detection_engine import DetectionEngine

from event_logger import EventLogger

from security_statistics import SecurityStatistics


# =====================================================
# CREATE COMPONENTS
# =====================================================

detection_engine = DetectionEngine()

event_logger = EventLogger()

statistics = SecurityStatistics()


# =====================================================
# HEADER
# =====================================================

print("\n" + "=" * 60)
print("END-TO-END SECURITY PIPELINE TEST")
print("=" * 60)

print(
    "\nPipeline:"
)

print(
    "Features → Detection Engine → "
    "Detection Event → Logger + Statistics"
)


# =====================================================
# HELPER FUNCTION
# =====================================================

def process_test(
    test_name,
    features
):
    """
    Send features through the complete
    detection pipeline.
    """

    print("\n" + "=" * 60)
    print(test_name)
    print("=" * 60)

    # ---------------------------------------------
    # Count packet
    # ---------------------------------------------

    statistics.record_packet()

    # ---------------------------------------------
    # Detection Engine
    # ---------------------------------------------

    result = detection_engine.analyze_packet(
        features
    )

    print(
        "Detection Result :"
    )

    if result is None:

        print(
            "None"
        )

        return None

    # ---------------------------------------------
    # Convert event to dictionary
    # ---------------------------------------------

    event_data = result.to_dict()

    print(
        event_data
    )

    # ---------------------------------------------
    # Record statistics
    # ---------------------------------------------

    statistics.record_event(
        result
    )

    # ---------------------------------------------
    # Log event
    # ---------------------------------------------

    try:

        event_logger.log_event(
            result
        )

        print(
            "Event Logging : SUCCESS"
        )

    except Exception as error:

        print(
            "Event Logging : FAILED"
        )

        print(
            f"Error : {error}"
        )

    return result


# =====================================================
# TEST 1 : NORMAL TRAFFIC
# =====================================================

normal_features = {

    "is_arp": False,

    "is_dns": False,

    "dns_query": None
}


normal_result = process_test(
    "TEST 1 : NORMAL TRAFFIC",
    normal_features
)


assert normal_result is None


# =====================================================
# TEST 2 : PHISHING
# =====================================================

phishing_features = {

    "is_arp": False,

    "is_dns": False,

    "dns_query":
        "secure-paypal-login.com"
}


phishing_result = process_test(
    "TEST 2 : PHISHING",
    phishing_features
)


assert phishing_result is not None

assert (
    phishing_result.to_dict()["attack_type"]
    == "POSSIBLE_PHISHING"
)


# =====================================================
# TEST 3 : NORMAL ARP
# =====================================================

normal_arp_features = {

    "is_arp": True,

    "is_dns": False,

    "arp_operation": 2,

    "arp_src_ip":
        "192.168.1.1",

    "arp_src_mac":
        "AA:AA:AA:AA:AA:AA",

    "arp_dst_ip":
        "192.168.1.5",

    "arp_dst_mac":
        "BB:BB:BB:BB:BB:BB"
}


normal_arp_result = process_test(
    "TEST 3 : NORMAL ARP",
    normal_arp_features
)


assert normal_arp_result is not None


# =====================================================
# TEST 4 : ARP SPOOFING
# =====================================================

spoofed_arp_features = {

    "is_arp": True,

    "is_dns": False,

    "arp_operation": 2,

    "arp_src_ip":
        "192.168.1.1",

    "arp_src_mac":
        "CC:CC:CC:CC:CC:CC",

    "arp_dst_ip":
        "192.168.1.5",

    "arp_dst_mac":
        "BB:BB:BB:BB:BB:BB"
}


arp_result = process_test(
    "TEST 4 : ARP SPOOFING",
    spoofed_arp_features
)


assert arp_result is not None

assert (
    arp_result.to_dict()["attack_type"]
    == "POSSIBLE_ARP_SPOOFING"
)


# =====================================================
# TEST 5 : NORMAL DNS
# =====================================================

normal_dns_features = {

    "is_arp": False,

    "is_dns": True,

    "dns_query":
        "example.com",

    "dns_query_type":
        "A",

    "dns_answers":
        ["93.184.216.34"],

    "src_ip":
        "192.168.1.5",

    "dst_ip":
        "8.8.8.8",

    "src_port":
        50000,

    "dst_port":
        53
}


normal_dns_result = process_test(
    "TEST 5 : NORMAL DNS",
    normal_dns_features
)


assert normal_dns_result is not None


# =====================================================
# TEST 6 : DNS SPOOFING
# =====================================================

spoofed_dns_features = {

    "is_arp": False,

    "is_dns": True,

    "dns_query":
        "example.com",

    "dns_query_type":
        "A",

    "dns_answers":
        ["5.6.7.8"],

    "src_ip":
        "192.168.1.5",

    "dst_ip":
        "8.8.8.8",

    "src_port":
        50000,

    "dst_port":
        53
}


dns_result = process_test(
    "TEST 6 : DNS SPOOFING",
    spoofed_dns_features
)


assert dns_result is not None

assert (
    dns_result.to_dict()["attack_type"]
    == "POSSIBLE_DNS_SPOOFING"
)


# =====================================================
# FINAL STATISTICS
# =====================================================

print("\n" + "=" * 60)
print("FINAL SECURITY STATISTICS")
print("=" * 60)

statistics.display_summary()


# =====================================================
# GET STATISTICS
# =====================================================

stats = statistics.get_statistics()


# =====================================================
# VERIFY STATISTICS
# =====================================================

print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)

print(
    f"Packets Processed : "
    f"{stats['total_packets']}"
)

print(
    f"Security Events   : "
    f"{stats['total_events']}"
)

print(
    f"ARP Spoofing      : "
    f"{stats['arp_spoofing_events']}"
)

print(
    f"DNS Spoofing      : "
    f"{stats['dns_spoofing_events']}"
)

print(
    f"Phishing          : "
    f"{stats['phishing_events']}"
)

print(
    f"HIGH              : "
    f"{stats['high_events']}"
)

print(
    f"MEDIUM            : "
    f"{stats['medium_events']}"
)

print(
    f"INFO              : "
    f"{stats['info_events']}"
)


# =====================================================
# ASSERTIONS
# =====================================================

assert (
    stats["total_packets"] == 6
)

assert (
    stats["phishing_events"] == 1
)

assert (
    stats["arp_spoofing_events"] == 1
)

assert (
    stats["dns_spoofing_events"] == 1
)


# =====================================================
# SUCCESS
# =====================================================

print("\n" + "=" * 60)
print("ALL END-TO-END TESTS PASSED")
print("=" * 60)

print(
    "\nComplete Member 1 pipeline is working:"
)

print(
    "Feature Extraction"
    " → Detection Engine"
    " → Detection Event"
    " → Event Logger"
    " → Security Statistics"
)