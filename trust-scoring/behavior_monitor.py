"""
behavior_monitor.py
-------------------
Member 2 - Device Behavior Monitor

Tracks security behavior of devices over time.

The monitor reads security events from the SQLite
database and summarizes the behavior of each device.

It does NOT block or isolate devices.

It provides information to the Trust Engine and
Policy Engine.
"""

import os
import sys


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
# DATABASE
# =====================================================

from database import (
    get_detections_by_source_ip,
    get_all_detections
)


# =====================================================
# BEHAVIOR MONITOR
# =====================================================

class BehaviorMonitor:

    def __init__(self):

        pass


    # =================================================
    # GET DEVICE EVENTS
    # =================================================

    def get_device_events(self, source_ip):

        """
        Get all security events associated with
        one device.
        """

        return get_detections_by_source_ip(
            source_ip
        )


    # =================================================
    # COUNT EVENT TYPES
    # =================================================

    def count_event_types(self, events):

        """
        Count different security event types.
        """

        counts = {

            "INFO": 0,

            "POSSIBLE_PHISHING": 0,

            "POSSIBLE_DNS_SPOOFING": 0,

            "POSSIBLE_ARP_SPOOFING": 0
        }


        for event in events:

            attack_type = event.get(
                "attack_type"
            )

            severity = event.get(
                "severity"
            )


            if attack_type in counts:

                counts[attack_type] += 1


            elif severity == "INFO":

                counts["INFO"] += 1


        return counts


    # =================================================
    # CALCULATE BEHAVIOR RISK
    # =================================================

    def calculate_behavior_risk(self, events):

        """
        Calculate a simple behavior risk score.

        This is different from the Trust Score.

        Behavior Risk:
            0   = no suspicious behavior
            100 = highly suspicious behavior
        """

        if not events:

            return 0


        risk = 0


        for event in events:

            attack_type = event.get(
                "attack_type"
            )

            risk_score = event.get(
                "risk_score",
                0
            )


            if attack_type in [
                "POSSIBLE_ARP_SPOOFING",
                "POSSIBLE_DNS_SPOOFING",
                "POSSIBLE_PHISHING"
            ]:

                risk += risk_score


        # ---------------------------------------------
        # Normalize to 0-100
        # ---------------------------------------------

        risk = min(
            100,
            risk
        )


        return risk


    # =================================================
    # GET BEHAVIOR STATUS
    # =================================================

    def get_behavior_status(
        self,
        behavior_risk
    ):

        """
        Convert behavior risk into a status.
        """

        if behavior_risk == 0:

            return "NORMAL"


        elif behavior_risk < 40:

            return "LOW_RISK"


        elif behavior_risk < 70:

            return "SUSPICIOUS"


        else:

            return "HIGH_RISK"


    # =================================================
    # ANALYZE DEVICE
    # =================================================

    def analyze_device(self, source_ip):

        """
        Analyze the complete behavior history
        of one device.
        """

        events = self.get_device_events(
            source_ip
        )


        event_counts = self.count_event_types(
            events
        )


        behavior_risk = (
            self.calculate_behavior_risk(
                events
            )
        )


        behavior_status = (
            self.get_behavior_status(
                behavior_risk
            )
        )


        return {

            "source_ip": source_ip,

            "total_events": len(events),

            "event_counts": event_counts,

            "behavior_risk": behavior_risk,

            "behavior_status": behavior_status
        }


# =====================================================
# GET ALL DEVICES
# =====================================================

def get_all_devices():

    """
    Get unique source IP addresses from
    the detection database.
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


    return sorted(
        devices
    )


# =====================================================
# DISPLAY DEVICE BEHAVIOR
# =====================================================

def display_behavior(result):

    print(
        "\n" + "-" * 70
    )

    print(
        f"DEVICE : {result['source_ip']}"
    )

    print(
        "-" * 70
    )

    print(
        f"Total Events  : "
        f"{result['total_events']}"
    )

    print(
        f"INFO          : "
        f"{result['event_counts']['INFO']}"
    )

    print(
        f"Phishing      : "
        f"{result['event_counts']['POSSIBLE_PHISHING']}"
    )

    print(
        f"DNS Spoofing  : "
        f"{result['event_counts']['POSSIBLE_DNS_SPOOFING']}"
    )

    print(
        f"ARP Spoofing  : "
        f"{result['event_counts']['POSSIBLE_ARP_SPOOFING']}"
    )

    print(
        f"Behavior Risk : "
        f"{result['behavior_risk']}"
    )

    print(
        f"Status        : "
        f"{result['behavior_status']}"
    )


# =====================================================
# TEST ALL DEVICES
# =====================================================

def run_behavior_monitor():

    print(
        "\n" + "=" * 70
    )

    print(
        "DEVICE BEHAVIOR MONITOR"
    )

    print(
        "=" * 70
    )


    monitor = BehaviorMonitor()


    devices = get_all_devices()


    if not devices:

        print(
            "\nNo devices found."
        )

        return


    print(
        f"\nDevices Found : "
        f"{len(devices)}"
    )


    for source_ip in devices:

        result = monitor.analyze_device(
            source_ip
        )

        display_behavior(
            result
        )


    print(
        "\n" + "=" * 70
    )

    print(
        "BEHAVIOR MONITORING COMPLETED"
    )

    print(
        "=" * 70
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    try:

        run_behavior_monitor()

    except Exception as error:

        print(
            "\nERROR:"
        )

        print(
            error
        )

        print(
            "\nCheck that:"
        )

        print(
            "1. packet_capture.db exists."
        )

        print(
            "2. database.py is accessible."
        )

        print(
            "3. get_all_detections() exists."
        )

        print(
            "4. get_detections_by_source_ip() exists."
        )