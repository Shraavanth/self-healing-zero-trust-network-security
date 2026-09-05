"""
TRAFFIC ISOLATION ENGINE
------------------------
Safe simulation of network traffic isolation.

This module simulates firewall rules using JSON.

IMPORTANT:
This does NOT modify the real Windows Firewall.
It only creates and manages simulated firewall rules.
"""

import os
import json
from datetime import datetime


# =====================================================
# FILE CONFIGURATION
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

FIREWALL_RULE_FILE = os.path.join(
    CURRENT_DIR,
    "firewall_rules.json"
)


# =====================================================
# TRAFFIC ISOLATION ENGINE
# =====================================================

class TrafficIsolationEngine:

    def __init__(self):

        self.firewall_rules = (
            self.load_rules()
        )


    # =================================================
    # LOAD FIREWALL RULES
    # =================================================

    def load_rules(self):

        if not os.path.exists(
            FIREWALL_RULE_FILE
        ):

            return {}

        try:

            with open(
                FIREWALL_RULE_FILE,
                "r"
            ) as file:

                data = json.load(file)

                if isinstance(data, dict):

                    return data

                return {}

        except (
            json.JSONDecodeError,
            OSError
        ):

            return {}


    # =================================================
    # SAVE FIREWALL RULES
    # =================================================

    def save_rules(self):

        with open(
            FIREWALL_RULE_FILE,
            "w"
        ) as file:

            json.dump(
                self.firewall_rules,
                file,
                indent=4
            )


    # =================================================
    # BLOCK DEVICE
    # =================================================

    def block_device(
        self,
        source_ip,
        reason,
        trust_score,
        behavior_risk
    ):

        # ---------------------------------------------
        # Prevent duplicate firewall rules
        # ---------------------------------------------

        if self.is_blocked(
            source_ip
        ):

            existing_rule = (
                self.firewall_rules[
                    source_ip
                ]
            )

            return {

                "source_ip":
                    source_ip,

                "action":
                    "BLOCK",

                "status":
                    "ALREADY_BLOCKED",

                "message":
                    "Traffic is already blocked",

                "created_at":
                    existing_rule.get(
                        "created_at"
                    )
            }


        # ---------------------------------------------
        # Create new firewall rule
        # ---------------------------------------------

        timestamp = (
            datetime.now().isoformat()
        )


        self.firewall_rules[
            source_ip
        ] = {

            "source_ip":
                source_ip,

            "action":
                "BLOCK",

            "status":
                "BLOCKED",

            "reason":
                reason,

            "trust_score":
                trust_score,

            "behavior_risk":
                behavior_risk,

            "created_at":
                timestamp
        }


        self.save_rules()


        return {

            "source_ip":
                source_ip,

            "action":
                "BLOCK",

            "status":
                "BLOCKED",

            "message":
                "Traffic blocked by simulated firewall",

            "created_at":
                timestamp
        }


    # =================================================
    # CHECK WHETHER DEVICE IS BLOCKED
    # =================================================

    def is_blocked(
        self,
        source_ip
    ):

        if source_ip not in self.firewall_rules:

            return False


        rule = (
            self.firewall_rules[
                source_ip
            ]
        )


        return (
            rule.get("status")
            == "BLOCKED"
        )


    # =================================================
    # CHECK TRAFFIC
    # =================================================

    def check_traffic(
        self,
        source_ip
    ):

        if self.is_blocked(
            source_ip
        ):

            return {

                "source_ip":
                    source_ip,

                "traffic":
                    "BLOCKED",

                "status":
                    "ISOLATED",

                "message":
                    "Traffic blocked by simulated firewall"
            }


        return {

            "source_ip":
                source_ip,

            "traffic":
                "ALLOWED",

            "status":
                "NORMAL",

            "message":
                "Traffic is allowed"
        }


    # =================================================
    # RELEASE DEVICE
    # =================================================

    def release_device(
        self,
        source_ip,
        reason="Threat cleared"
    ):

        if not self.is_blocked(
            source_ip
        ):

            return {

                "source_ip":
                    source_ip,

                "action":
                    "RELEASE",

                "status":
                    "NOT_BLOCKED",

                "message":
                    "No active traffic isolation rule exists"
            }


        # ---------------------------------------------
        # Remove firewall rule
        # ---------------------------------------------

        del self.firewall_rules[
            source_ip
        ]


        self.save_rules()


        return {

            "source_ip":
                source_ip,

            "action":
                "RELEASE",

            "status":
                "RELEASED",

            "message":
                "Traffic isolation rule removed",

            "reason":
                reason,

            "released_at":
                datetime.now().isoformat()
        }


    # =================================================
    # GET ALL FIREWALL RULES
    # =================================================

    def get_all_rules(self):

        return self.firewall_rules


    # =================================================
    # DISPLAY FIREWALL RULES
    # =================================================

    def display_rules(self):

        print(
            "\n" + "=" * 80
        )

        print(
            "SIMULATED FIREWALL RULES"
        )

        print(
            "=" * 80
        )


        if not self.firewall_rules:

            print(
                "\nNo active firewall rules."
            )

            return


        for source_ip, rule in (
            self.firewall_rules.items()
        ):

            print(
                "\n" + "-" * 80
            )

            print(
                "Source IP     : "
                + source_ip
            )

            print(
                "Action        : "
                + str(
                    rule.get(
                        "action",
                        "N/A"
                    )
                )
            )

            print(
                "Status        : "
                + str(
                    rule.get(
                        "status",
                        "N/A"
                    )
                )
            )

            print(
                "Reason        : "
                + str(
                    rule.get(
                        "reason",
                        "N/A"
                    )
                )
            )

            print(
                "Trust Score   : "
                + str(
                    rule.get(
                        "trust_score",
                        "N/A"
                    )
                )
            )

            print(
                "Behavior Risk : "
                + str(
                    rule.get(
                        "behavior_risk",
                        "N/A"
                    )
                )
            )

            print(
                "Created At    : "
                + str(
                    rule.get(
                        "created_at",
                        "N/A"
                    )
                )
            )


# =====================================================
# TESTING
# =====================================================

def run_tests():

    print(
        "\n" + "=" * 80
    )

    print(
        "TRAFFIC ISOLATION ENGINE"
    )

    print(
        "=" * 80
    )

    print(
        "\nMode : SAFE SIMULATION"
    )

    print(
        "Real Windows Firewall will NOT be modified."
    )


    engine = (
        TrafficIsolationEngine()
    )


    # =================================================
    # TEST 1
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 1 : BLOCK MALICIOUS DEVICE"
    )

    print(
        "-" * 80
    )


    response = (
        engine.block_device(
            source_ip="192.0.2.40",
            reason="High behavioral risk",
            trust_score=28,
            behavior_risk=100
        )
    )


    print(
        "Source IP : "
        + response["source_ip"]
    )

    print(
        "Action    : "
        + response["action"]
    )

    print(
        "Status    : "
        + response["status"]
    )

    print(
        "Message   : "
        + response["message"]
    )


    # =================================================
    # TEST 2
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 2 : CHECK BLOCKED TRAFFIC"
    )

    print(
        "-" * 80
    )


    traffic = (
        engine.check_traffic(
            "192.0.2.40"
        )
    )


    print(
        "Source IP : "
        + traffic["source_ip"]
    )

    print(
        "Traffic   : "
        + traffic["traffic"]
    )

    print(
        "Status    : "
        + traffic["status"]
    )

    print(
        "Message   : "
        + traffic["message"]
    )


    # =================================================
    # TEST 3
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 3 : CHECK NORMAL DEVICE"
    )

    print(
        "-" * 80
    )


    traffic = (
        engine.check_traffic(
            "192.0.2.10"
        )
    )


    print(
        "Source IP : "
        + traffic["source_ip"]
    )

    print(
        "Traffic   : "
        + traffic["traffic"]
    )

    print(
        "Status    : "
        + traffic["status"]
    )

    print(
        "Message   : "
        + traffic["message"]
    )


    # =================================================
    # TEST 4
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 4 : CURRENT FIREWALL RULES"
    )

    print(
        "-" * 80
    )


    engine.display_rules()


    # =================================================
    # TEST 5
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 5 : RELEASE DEVICE"
    )

    print(
        "-" * 80
    )


    response = (
        engine.release_device(
            "192.0.2.40",
            "Threat cleared"
        )
    )


    print(
        "Source IP : "
        + response["source_ip"]
    )

    print(
        "Action    : "
        + response["action"]
    )

    print(
        "Status    : "
        + response["status"]
    )

    print(
        "Message   : "
        + response["message"]
    )


    # =================================================
    # TEST 6
    # =================================================

    print(
        "\n" + "-" * 80
    )

    print(
        "TEST 6 : CHECK TRAFFIC AFTER RELEASE"
    )

    print(
        "-" * 80
    )


    traffic = (
        engine.check_traffic(
            "192.0.2.40"
        )
    )


    print(
        "Source IP : "
        + traffic["source_ip"]
    )

    print(
        "Traffic   : "
        + traffic["traffic"]
    )

    print(
        "Status    : "
        + traffic["status"]
    )

    print(
        "Message   : "
        + traffic["message"]
    )


    print(
        "\n" + "=" * 80
    )

    print(
        "TRAFFIC ISOLATION TEST COMPLETED"
    )

    print(
        "=" * 80
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    run_tests()