"""
policy_engine.py
----------------
Zero Trust Policy Engine

Converts a device's trust score and behavior risk
into a Zero Trust access policy.

Trust Levels:

80-100 -> TRUSTED  -> ALLOW
60-79  -> MONITOR  -> MONITOR
30-59  -> RESTRICT -> RESTRICT
0-29   -> ISOLATE  -> ISOLATE

Behavior Risk:

0-69   -> Normal policy evaluation
70-100 -> Immediate ISOLATE
"""


# =====================================================
# TRUST THRESHOLDS
# =====================================================

TRUSTED_MIN = 80

MONITOR_MIN = 60

RESTRICT_MIN = 30


# =====================================================
# BEHAVIOR RISK THRESHOLD
# =====================================================

HIGH_BEHAVIOR_RISK = 70


# =====================================================
# POLICY ENGINE
# =====================================================

class PolicyEngine:

    def __init__(self):

        pass


    # =================================================
    # GET TRUST LEVEL
    # =================================================

    def get_trust_level(self, trust_score):

        """
        Convert numerical trust score into
        a trust level.
        """

        if trust_score >= TRUSTED_MIN:

            return "TRUSTED"

        elif trust_score >= MONITOR_MIN:

            return "MONITOR"

        elif trust_score >= RESTRICT_MIN:

            return "RESTRICT"

        else:

            return "ISOLATE"


    # =================================================
    # GET ACCESS DECISION
    # =================================================

    def get_access_decision(
        self,
        trust_score,
        behavior_risk=0
    ):

        """
        Determine Zero Trust access decision using
        both trust score and behavior risk.
        """

        # ---------------------------------------------
        # High behavior risk
        # ---------------------------------------------

        if behavior_risk >= HIGH_BEHAVIOR_RISK:

            return "ISOLATE"


        # ---------------------------------------------
        # Trust-score based decision
        # ---------------------------------------------

        if trust_score >= TRUSTED_MIN:

            return "ALLOW"

        elif trust_score >= MONITOR_MIN:

            return "MONITOR"

        elif trust_score >= RESTRICT_MIN:

            return "RESTRICT"

        else:

            return "ISOLATE"


    # =================================================
    # GET POLICY DETAILS
    # =================================================

    def evaluate(
        self,
        source_ip,
        trust_score,
        behavior_risk=0
    ):

        """
        Evaluate a device using trust score
        and behavior risk.
        """

        # ---------------------------------------------
        # Determine trust level
        # ---------------------------------------------

        trust_level = self.get_trust_level(
            trust_score
        )


        # ---------------------------------------------
        # Determine access decision
        # ---------------------------------------------

        decision = self.get_access_decision(
            trust_score,
            behavior_risk
        )


        # ---------------------------------------------
        # ALLOW
        # ---------------------------------------------

        if decision == "ALLOW":

            action = (
                "Allow normal network access"
            )

            reason = (
                "Device has a high trust score "
                "and acceptable behavior risk"
            )


        # ---------------------------------------------
        # MONITOR
        # ---------------------------------------------

        elif decision == "MONITOR":

            action = (
                "Allow access with increased monitoring"
            )

            reason = (
                "Device trust has decreased"
            )


        # ---------------------------------------------
        # RESTRICT
        # ---------------------------------------------

        elif decision == "RESTRICT":

            action = (
                "Limit network access"
            )

            reason = (
                "Device has a low trust score"
            )


        # ---------------------------------------------
        # ISOLATE
        # ---------------------------------------------

        else:

            action = (
                "Block or isolate the device"
            )


            if behavior_risk >= HIGH_BEHAVIOR_RISK:

                reason = (
                    "Behavior risk is critically high"
                )

            else:

                reason = (
                    "Device trust score is critically low"
                )


        # ---------------------------------------------
        # Return policy
        # ---------------------------------------------

        return {

            "source_ip": source_ip,

            "trust_score": trust_score,

            "behavior_risk": behavior_risk,

            "trust_level": trust_level,

            "decision": decision,

            "action": action,

            "reason": reason
        }


# =====================================================
# TEST POLICY ENGINE
# =====================================================

def run_policy_tests():

    print(
        "\n" + "=" * 80
    )

    print(
        "ZERO TRUST POLICY ENGINE"
    )

    print(
        "=" * 80
    )


    # =================================================
    # TEST DEVICES
    # =================================================

    test_devices = [

        # High trust + normal behavior
        ("192.0.2.10", 98, 0),

        # Medium trust + medium behavior
        ("192.0.2.20", 70, 50),

        # Low trust + medium behavior
        ("192.0.2.30", 50, 60),

        # Very low trust + high behavior risk
        ("192.0.2.40", 28, 100),

        # Real device example
        ("192.168.1.1", 92, 0),

        # Real device with critically low trust
        ("192.168.1.5", 0, 100)
    ]


    engine = PolicyEngine()


    # =================================================
    # TABLE HEADER
    # =================================================

    print(
        "\n"
        f"{'SOURCE IP':<20}"
        f"{'TRUST':<10}"
        f"{'BEHAVIOR':<12}"
        f"{'LEVEL':<12}"
        f"{'DECISION'}"
    )

    print(
        "-" * 80
    )


    # =================================================
    # EVALUATE DEVICES
    # =================================================

    for (
        source_ip,
        trust_score,
        behavior_risk
    ) in test_devices:

        result = engine.evaluate(
            source_ip,
            trust_score,
            behavior_risk
        )


        print(
            f"{result['source_ip']:<20}"
            f"{result['trust_score']:<10}"
            f"{result['behavior_risk']:<12}"
            f"{result['trust_level']:<12}"
            f"{result['decision']}"
        )


    # =================================================
    # DETAILED EXAMPLE
    # =================================================

    print(
        "\n" + "=" * 80
    )

    print(
        "DETAILED POLICY EXAMPLE"
    )

    print(
        "=" * 80
    )


    result = engine.evaluate(
        "192.0.2.40",
        28,
        100
    )


    print(
        f"\nSource IP    : "
        f"{result['source_ip']}"
    )

    print(
        f"Trust Score  : "
        f"{result['trust_score']}"
    )

    print(
        f"Behavior Risk: "
        f"{result['behavior_risk']}"
    )

    print(
        f"Trust Level  : "
        f"{result['trust_level']}"
    )

    print(
        f"Decision     : "
        f"{result['decision']}"
    )

    print(
        f"Action       : "
        f"{result['action']}"
    )

    print(
        f"Reason       : "
        f"{result['reason']}"
    )


    # =================================================
    # COMPLETION
    # =================================================

    print(
        "\n" + "=" * 80
    )

    print(
        "POLICY ENGINE TEST COMPLETED"
    )

    print(
        "=" * 80
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    run_policy_tests()