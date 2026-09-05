"""
trust_score.py
--------------
Member 2 - Dynamic Trust Scoring

Reads real security events from the SQLite database
created by Member 1 and calculates a separate trust
score for every source IP address.

Database:
    ../packet-monitoring/db/packet_capture.db

Trust Score:
    Initial = 100

Penalties:
    INFO                  -> -2
    POSSIBLE_PHISHING     -> -15
    POSSIBLE_DNS_SPOOFING -> -25
    POSSIBLE_ARP_SPOOFING -> -30

Trust Levels:
    80-100 -> TRUSTED
    60-79  -> MONITOR
    30-59  -> RESTRICT
    0-29   -> ISOLATE
"""

import os
import sys
from collections import defaultdict


# =====================================================
# PROJECT PATH SETUP
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)

PACKET_MONITORING_DIR = os.path.join(
    PROJECT_ROOT,
    "packet-monitoring"
)

if PACKET_MONITORING_DIR not in sys.path:

    sys.path.insert(
        0,
        PACKET_MONITORING_DIR
    )


# =====================================================
# IMPORT DATABASE FUNCTIONS
# =====================================================

from database import (
    get_all_detections,
    get_detections_by_source_ip
)


# =====================================================
# TRUST SCORE CONFIGURATION
# =====================================================

INITIAL_TRUST_SCORE = 100

MIN_TRUST_SCORE = 0

MAX_TRUST_SCORE = 100


# =====================================================
# EVENT PENALTIES
# =====================================================

EVENT_PENALTIES = {

    "INFO": 2,

    "POSSIBLE_PHISHING": 15,

    "POSSIBLE_DNS_SPOOFING": 25,

    "POSSIBLE_ARP_SPOOFING": 30
}


# =====================================================
# TRUST SCORE CALCULATOR
# =====================================================

class TrustScoreCalculator:

    def __init__(self):

        self.initial_score = (
            INITIAL_TRUST_SCORE
        )


    # =================================================
    # CALCULATE TRUST SCORE
    # =================================================

    def calculate(self, events):

        """
        Calculate trust score from security
        events belonging to one IP address.
        """

        score = self.initial_score

        for event in events:

            attack_type = event.get(
                "attack_type"
            )

            severity = event.get(
                "severity",
                "INFO"
            )


            # -----------------------------------------
            # Attack-based penalty
            # -----------------------------------------

            if attack_type in EVENT_PENALTIES:

                penalty = EVENT_PENALTIES[
                    attack_type
                ]

                score -= penalty


            # -----------------------------------------
            # Informational event
            # -----------------------------------------

            elif severity == "INFO":

                score -= EVENT_PENALTIES[
                    "INFO"
                ]


        # ---------------------------------------------
        # Keep score between 0 and 100
        # ---------------------------------------------

        score = max(
            MIN_TRUST_SCORE,
            min(
                MAX_TRUST_SCORE,
                score
            )
        )

        return score


    # =================================================
    # TRUST LEVEL
    # =================================================

    def get_trust_level(self, score):

        if score >= 80:

            return "TRUSTED"

        elif score >= 60:

            return "MONITOR"

        elif score >= 30:

            return "RESTRICT"

        else:

            return "ISOLATE"


# =====================================================
# GET ALL DEVICES
# =====================================================

def get_all_devices():

    """
    Get all unique source IP addresses from
    the security detection database.
    """

    detections = get_all_detections()

    devices = set()

    for detection in detections:

        source_ip = detection.get(
            "source_ip"
        )

        if source_ip:

            devices.add(
                source_ip
            )

    return sorted(devices)


# =====================================================
# CALCULATE TRUST FOR ONE IP
# =====================================================

def calculate_trust_for_ip(
    source_ip,
    show_history=True
):

    """
    Calculate trust score for one source IP.
    """

    events = get_detections_by_source_ip(
        source_ip
    )

    calculator = TrustScoreCalculator()

    trust_score = calculator.calculate(
        events
    )

    trust_level = calculator.get_trust_level(
        trust_score
    )


    # ---------------------------------------------
    # Display history
    # ---------------------------------------------

    if show_history:

        print(
            "\n" + "-" * 60
        )

        print(
            f"DEVICE: {source_ip}"
        )

        print(
            "-" * 60
        )

        print(
            f"Events Found : {len(events)}"
        )

        for index, event in enumerate(
            events,
            1
        ):

            print(
                f"\nEvent {index}"
            )

            print(
                f"  Attack Type : "
                f"{event.get('attack_type')}"
            )

            print(
                f"  Severity    : "
                f"{event.get('severity')}"
            )

            print(
                f"  Confidence  : "
                f"{event.get('confidence')}"
            )

            print(
                f"  Risk Score  : "
                f"{event.get('risk_score')}"
            )

            print(
                f"  Domain      : "
                f"{event.get('domain')}"
            )

            print(
                f"  Message     : "
                f"{event.get('message')}"
            )


        print(
            "\nTrust Assessment"
        )

        print(
            "-" * 60
        )

        print(
            f"Initial Trust : "
            f"{INITIAL_TRUST_SCORE}"
        )

        print(
            f"Final Trust   : "
            f"{trust_score}"
        )

        print(
            f"Trust Level   : "
            f"{trust_level}"
        )


    return {
        "source_ip": source_ip,
        "event_count": len(events),
        "trust_score": trust_score,
        "trust_level": trust_level
    }


# =====================================================
# CALCULATE TRUST FOR ALL DEVICES
# =====================================================

def calculate_trust_for_all_devices():

    """
    Automatically discover every device/IP in the
    SQLite database and calculate an independent
    trust score for each device.
    """

    print(
        "\n" + "=" * 70
    )

    print(
        "MEMBER 2 : DYNAMIC TRUST SCORING"
    )

    print(
        "=" * 70
    )


    # ---------------------------------------------
    # Find all devices
    # ---------------------------------------------

    devices = get_all_devices()


    if not devices:

        print(
            "\nNo devices found in database."
        )

        return []


    print(
        f"\nDevices Found : {len(devices)}"
    )

    for device in devices:

        print(
            f"  - {device}"
        )


    # ---------------------------------------------
    # Calculate each device independently
    # ---------------------------------------------

    results = []

    for source_ip in devices:

        result = calculate_trust_for_ip(
            source_ip,
            show_history=False
        )

        results.append(
            result
        )


    # =================================================
    # FINAL DEVICE TRUST TABLE
    # =================================================

    print(
        "\n\n" + "=" * 70
    )

    print(
        "ZERO TRUST DEVICE ASSESSMENT"
    )

    print(
        "=" * 70
    )

    print(
        f"{'SOURCE IP':<20}"
        f"{'EVENTS':<10}"
        f"{'TRUST SCORE':<15}"
        f"{'TRUST LEVEL'}"
    )

    print(
        "-" * 70
    )


    for result in results:

        print(
            f"{result['source_ip']:<20}"
            f"{result['event_count']:<10}"
            f"{result['trust_score']:<15}"
            f"{result['trust_level']}"
        )


    print(
        "=" * 70
    )


    return results


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    try:

        calculate_trust_for_all_devices()

    except Exception as error:

        print(
            "\nERROR:"
        )

        print(
            error
        )

        print(
            "\nMake sure:"
        )

        print(
            "1. packet_capture.db exists."
        )

        print(
            "2. database.py is working."
        )

        print(
            "3. get_all_detections() exists."
        )

        print(
            "4. get_detections_by_source_ip() exists."
        )

        print(
            "5. The database path is correct."
        )