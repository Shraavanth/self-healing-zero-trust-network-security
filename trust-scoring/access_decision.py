"""
access_decision.py
------------------
Zero Trust Access Decision Module.

Uses:

1. Trust Score
2. Behavior Risk
3. Policy Engine

to determine the final access decision.
"""

from policy_engine import PolicyEngine


# =====================================================
# ACCESS DECISION ENGINE
# =====================================================

class AccessDecision:

    def __init__(self):

        self.policy_engine = PolicyEngine()


    # =================================================
    # MAKE DECISION
    # =================================================

    def decide(
        self,
        source_ip,
        trust_score,
        behavior_risk=0
    ):

        """
        Make a Zero Trust access decision using
        trust score and behavior risk.
        """

        # ---------------------------------------------
        # Get policy decision
        # ---------------------------------------------

        policy = self.policy_engine.evaluate(
            source_ip,
            trust_score,
            behavior_risk
        )

        decision = policy["decision"]


        # ---------------------------------------------
        # ALLOW
        # ---------------------------------------------

        if decision == "ALLOW":

            enforcement = "NORMAL_ACCESS"

            message = (
                "Device is trusted. "
                "Normal network access is permitted."
            )


        # ---------------------------------------------
        # MONITOR
        # ---------------------------------------------

        elif decision == "MONITOR":

            enforcement = "ENHANCED_MONITORING"

            message = (
                "Device access is permitted, "
                "but additional monitoring is required."
            )


        # ---------------------------------------------
        # RESTRICT
        # ---------------------------------------------

        elif decision == "RESTRICT":

            enforcement = "LIMIT_ACCESS"

            message = (
                "Device has reduced trust. "
                "Network access should be restricted."
            )


        # ---------------------------------------------
        # ISOLATE
        # ---------------------------------------------

        else:

            enforcement = "ISOLATE_DEVICE"

            message = (
                "Device has critically low trust "
                "or high behavioral risk. "
                "Device should be isolated."
            )


        # ---------------------------------------------
        # Return decision
        # ---------------------------------------------

        return {

            "source_ip":
                source_ip,

            "trust_score":
                trust_score,

            "behavior_risk":
                behavior_risk,

            "trust_level":
                policy["trust_level"],

            "decision":
                decision,

            "enforcement":
                enforcement,

            "message":
                message
        }


# =====================================================
# DISPLAY DECISION
# =====================================================

def display_decision(result):

    print(
        "\n" + "-" * 70
    )

    print(
        "ACCESS DECISION"
    )

    print(
        "-" * 70
    )

    print(
        f"Source IP     : "
        f"{result['source_ip']}"
    )

    print(
        f"Trust Score   : "
        f"{result['trust_score']}"
    )

    print(
        f"Behavior Risk : "
        f"{result['behavior_risk']}"
    )

    print(
        f"Trust Level   : "
        f"{result['trust_level']}"
    )

    print(
        f"Decision      : "
        f"{result['decision']}"
    )

    print(
        f"Enforcement   : "
        f"{result['enforcement']}"
    )

    print(
        f"Message       : "
        f"{result['message']}"
    )


# =====================================================
# TEST
# =====================================================

def run_tests():

    print(
        "\n" + "=" * 70
    )

    print(
        "ZERO TRUST ACCESS DECISION"
    )

    print(
        "=" * 70
    )


    test_devices = [

        # IP, Trust Score, Behavior Risk

        ("192.0.2.10", 98, 0),

        ("192.0.2.20", 70, 50),

        ("192.0.2.30", 50, 60),

        ("192.0.2.40", 28, 100),

        ("192.168.1.1", 92, 0),

        ("192.168.1.5", 0, 100)
    ]


    engine = AccessDecision()


    for (
        source_ip,
        trust_score,
        behavior_risk
    ) in test_devices:

        result = engine.decide(
            source_ip,
            trust_score,
            behavior_risk
        )

        display_decision(
            result
        )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    run_tests()