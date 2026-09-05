"""
test_attack_scenarios.py
------------------------
Member 2 testing utility.

Safely tests:
1. ARP Spoofing
2. DNS Spoofing
3. Phishing

The test does NOT perform an actual network attack.

It creates synthetic packet features and sends them
through Member 1's DetectionEngine.

Detected events are also inserted into Member 1's
SQLite database so that the Trust Engine can use them.
"""

import os
import sys


# =====================================================
# PATH SETUP
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)

PHISHING_DETECTION_DIR = os.path.join(
    PROJECT_ROOT,
    "phishing-spoofing-detection"
)

PACKET_MONITORING_DIR = os.path.join(
    PROJECT_ROOT,
    "packet-monitoring"
)


if PHISHING_DETECTION_DIR not in sys.path:

    sys.path.insert(
        0,
        PHISHING_DETECTION_DIR
    )


if PACKET_MONITORING_DIR not in sys.path:

    sys.path.insert(
        0,
        PACKET_MONITORING_DIR
    )


# =====================================================
# IMPORT MEMBER 1 MODULES
# =====================================================

from detection_engine import DetectionEngine

from database import insert_detection


# =====================================================
# TEST DEVICE
# =====================================================

TEST_IP = "192.168.1.5"

TEST_MAC = "c8:6e:08:58:69:20"

DNS_SERVER_IP = "192.168.1.1"

DNS_SERVER_MAC = "20:0c:86:81:42:b0"


# =====================================================
# DISPLAY EVENT
# =====================================================

def display_event(event):

    if event is None:

        print("Result : None")

        return


    print(
        "Result :"
    )

    print(
        event.to_dict()
        if hasattr(event, "to_dict")
        else event.__dict__
    )


# =====================================================
# SAVE EVENT TO DATABASE
# =====================================================

def save_event(event):

    if event is None:

        return


    # DetectionEvent may provide to_dict()
    # or we can use __dict__.

    if hasattr(event, "to_dict"):

        data = event.to_dict()

    else:

        data = event.__dict__.copy()


    # Remove fields that are not part of
    # the detections table.

    allowed_fields = {

        "attack_type",
        "source_ip",
        "source_mac",
        "domain",
        "severity",
        "confidence",
        "risk_score",
        "message"
    }


    data = {

        key: value

        for key, value in data.items()

        if key in allowed_fields
    }


    insert_detection(
        data
    )


    print(
        "Database Logging : SUCCESS"
    )


# =====================================================
# MAIN TEST
# =====================================================

if __name__ == "__main__":

    print(
        "\n" + "=" * 70
    )

    print(
        "MEMBER 2 : ATTACK SCENARIO TEST"
    )

    print(
        "=" * 70
    )

    print(
        f"\nTest Device : {TEST_IP}"
    )

    print(
        f"MAC Address : {TEST_MAC}"
    )


    engine = DetectionEngine()


    # =================================================
    # TEST 1 : ARP SPOOFING
    # =================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "TEST 1 : ARP SPOOFING"
    )

    print(
        "=" * 70
    )


    # First establish the legitimate mapping.

    normal_arp = {

        "is_arp": True,

        "is_dns": False,

        "src_ip": TEST_IP,

        "src_mac": TEST_MAC,

        "dst_ip": DNS_SERVER_IP,

        "dst_mac": DNS_SERVER_MAC,

        "arp_src_ip": TEST_IP,

        "arp_src_mac": TEST_MAC,

        "arp_dst_ip": DNS_SERVER_IP,

        "arp_dst_mac": DNS_SERVER_MAC
    }


    engine.analyze_packet(
        normal_arp
    )


    # Now use a different MAC for the
    # same IP.

    spoofed_arp = {

        "is_arp": True,

        "is_dns": False,

        "src_ip": TEST_IP,

        "src_mac": "AA:AA:AA:AA:AA:AA",

        "dst_ip": DNS_SERVER_IP,

        "dst_mac": DNS_SERVER_MAC,

        "arp_src_ip": TEST_IP,

        "arp_src_mac": "AA:AA:AA:AA:AA:AA",

        "arp_dst_ip": DNS_SERVER_IP,

        "arp_dst_mac": DNS_SERVER_MAC
    }


    arp_event = engine.analyze_packet(
        spoofed_arp
    )


    display_event(
        arp_event
    )


    if arp_event is not None:

        save_event(
            arp_event
        )


    # =================================================
    # TEST 2 : DNS SPOOFING
    # =================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "TEST 2 : DNS SPOOFING"
    )

    print(
        "=" * 70
    )


    # First create a legitimate DNS mapping.

    normal_dns = {

        "is_arp": False,

        "is_dns": True,

        "src_ip": TEST_IP,

        "src_mac": TEST_MAC,

        "dst_ip": DNS_SERVER_IP,

        "dst_mac": DNS_SERVER_MAC,

        "src_port": 50000,

        "dst_port": 53,

        "dns_query": "example-test.com",

        "dns_query_type": "A",

        "dns_answers": [
            "93.184.216.34"
        ]
    }


    engine.analyze_packet(
        normal_dns
    )


    # Now change the DNS answer.

    spoofed_dns = {

        "is_arp": False,

        "is_dns": True,

        "src_ip": DNS_SERVER_IP,

        "src_mac": DNS_SERVER_MAC,

        "dst_ip": TEST_IP,

        "dst_mac": TEST_MAC,

        "src_port": 53,

        "dst_port": 50000,

        "dns_query": "example-test.com",

        "dns_query_type": "A",

        "dns_answers": [
            "10.0.0.50"
        ]
    }


    dns_event = engine.analyze_packet(
        spoofed_dns
    )


    display_event(
        dns_event
    )


    if dns_event is not None:

        save_event(
            dns_event
        )


    # =================================================
    # TEST 3 : PHISHING
    # =================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "TEST 3 : PHISHING"
    )

    print(
        "=" * 70
    )


    phishing_features = {

        "is_arp": False,

        "is_dns": False,

        "src_ip": TEST_IP,

        "src_mac": TEST_MAC,

        "dst_ip": DNS_SERVER_IP,

        "dst_mac": DNS_SERVER_MAC,

        "src_port": 50001,

        "dst_port": 53,

        "dns_query":
            "secure-paypal-login.com"
    }


    phishing_event = engine.analyze_packet(
        phishing_features
    )


    display_event(
        phishing_event
    )


    if phishing_event is not None:

        save_event(
            phishing_event
        )

    # =====================================================
# TEST 4 : MULTIPLE DEVICE TRUST SCENARIOS
# =====================================================

print(
    "\n" + "=" * 70
)

print(
    "TEST 4 : MULTIPLE DEVICE TRUST SCENARIOS"
)

print(
    "=" * 70
)


# =====================================================
# TEST DEVICES
# =====================================================

test_devices = {

    # -------------------------------------------------
    # DEVICE 1
    # 1 INFO event
    #
    # 100 - 2 = 98
    # -------------------------------------------------

    "192.0.2.10": [

        {
            "attack_type": None,
            "source_ip": "192.0.2.10",
            "source_mac": "00:00:5e:00:53:10",
            "domain": None,
            "severity": "INFO",
            "confidence": 0.0,
            "risk_score": 0,
            "message": "Normal device activity"
        }

    ],


    # -------------------------------------------------
    # DEVICE 2
    # 2 phishing events
    #
    # 100 - 15 - 15 = 70
    # -------------------------------------------------

    "192.0.2.20": [

        {
            "attack_type": "POSSIBLE_PHISHING",
            "source_ip": "192.0.2.20",
            "source_mac": "00:00:5e:00:53:20",
            "domain": "secure-login-test.com",
            "severity": "MEDIUM",
            "confidence": 0.4,
            "risk_score": 40,
            "message": "Suspicious phishing domain"
        },

        {
            "attack_type": "POSSIBLE_PHISHING",
            "source_ip": "192.0.2.20",
            "source_mac": "00:00:5e:00:53:20",
            "domain": "verify-account-test.com",
            "severity": "MEDIUM",
            "confidence": 0.4,
            "risk_score": 40,
            "message": "Suspicious phishing domain"
        }

    ],


    # -------------------------------------------------
    # DEVICE 3
    # 2 DNS spoofing events
    #
    # 100 - 25 - 25 = 50
    # -------------------------------------------------

    "192.0.2.30": [

        {
            "attack_type": "POSSIBLE_DNS_SPOOFING",
            "source_ip": "192.0.2.30",
            "source_mac": "00:00:5e:00:53:30",
            "domain": "example-test.com",
            "severity": "MEDIUM",
            "confidence": 0.7,
            "risk_score": 70,
            "message": "DNS answer mapping changed"
        },

        {
            "attack_type": "POSSIBLE_DNS_SPOOFING",
            "source_ip": "192.0.2.30",
            "source_mac": "00:00:5e:00:53:30",
            "domain": "example-test.org",
            "severity": "MEDIUM",
            "confidence": 0.7,
            "risk_score": 70,
            "message": "DNS answer mapping changed"
        }

    ],


    # -------------------------------------------------
    # DEVICE 4
    # ARP + DNS + Phishing + INFO
    #
    # 100 - 30 - 25 - 15 - 2 = 28
    # -------------------------------------------------

    "192.0.2.40": [

        {
            "attack_type": "POSSIBLE_ARP_SPOOFING",
            "source_ip": "192.0.2.40",
            "source_mac": "00:00:5e:00:53:40",
            "domain": None,
            "severity": "HIGH",
            "confidence": 0.75,
            "risk_score": 75,
            "message": "IP-MAC mapping changed"
        },

        {
            "attack_type": "POSSIBLE_DNS_SPOOFING",
            "source_ip": "192.0.2.40",
            "source_mac": "00:00:5e:00:53:40",
            "domain": "example-test.net",
            "severity": "MEDIUM",
            "confidence": 0.7,
            "risk_score": 70,
            "message": "DNS answer mapping changed"
        },

        {
            "attack_type": "POSSIBLE_PHISHING",
            "source_ip": "192.0.2.40",
            "source_mac": "00:00:5e:00:53:40",
            "domain": "secure-bank-login-test.com",
            "severity": "MEDIUM",
            "confidence": 0.4,
            "risk_score": 40,
            "message": "Suspicious phishing domain"
        },

        {
            "attack_type": None,
            "source_ip": "192.0.2.40",
            "source_mac": "00:00:5e:00:53:40",
            "domain": None,
            "severity": "INFO",
            "confidence": 0.0,
            "risk_score": 0,
            "message": "Normal device activity"
        }

    ]
}


# =====================================================
# INSERT TEST DEVICES INTO DATABASE
# =====================================================

for ip_address, events in test_devices.items():

    print(
        f"\nAdding test history for {ip_address}"
    )

    for event in events:

        insert_detection(
            event
        )

        print(
            f"  Added: "
            f"{event['attack_type'] or 'INFO'}"
        )


        print(
            "\nTest device histories added successfully."
        )


    # =================================================
    # COMPLETE
    # =================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "ATTACK SCENARIO TEST COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        "\nExpected detections:"
    )

    print(
        "  ARP Spoofing  -> POSSIBLE_ARP_SPOOFING"
    )

    print(
        "  DNS Spoofing  -> POSSIBLE_DNS_SPOOFING"
    )

    print(
        "  Phishing      -> POSSIBLE_PHISHING"
    )

    print(
        "\nEvents were inserted into SQLite."
    )