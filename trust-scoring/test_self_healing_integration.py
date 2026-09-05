"""
test_self_healing_integration.py

Controlled test for the self-healing mechanism.

Tests two scenarios:

1. NORMAL ISOLATED DEVICE
   Threat cleared
   -> Isolation released
   -> Traffic unblocked
   -> Honeypot stopped
   -> Device recovered

2. PERMANENT REPEAT OFFENDER
   -> Must remain isolated
   -> Must remain blocked
   -> Must NOT be recovered automatically
"""

import os
import sys


# ============================================================
# PATH CONFIGURATION
# ============================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)


if CURRENT_DIR not in sys.path:

    sys.path.insert(
        0,
        CURRENT_DIR
    )


HONEYPOT_DIR = os.path.join(
    PROJECT_ROOT,
    "honeypot"
)


TRAFFIC_ISOLATION_DIR = os.path.join(
    PROJECT_ROOT,
    "traffic-isolation"
)


if HONEYPOT_DIR not in sys.path:

    sys.path.insert(
        0,
        HONEYPOT_DIR
    )


if TRAFFIC_ISOLATION_DIR not in sys.path:

    sys.path.insert(
        0,
        TRAFFIC_ISOLATION_DIR
    )


# ============================================================
# IMPORTS
# ============================================================

from isolation_manager import (
    IsolationManager
)

from traffic_isolation import (
    TrafficIsolationEngine
)

from honeypot import (
    HoneypotManager
)

from repeat_offender import (
    RepeatOffenderManager
)


# ============================================================
# TEST IPS
# ============================================================

RECOVERY_TEST_IP = (
    "192.0.2.100"
)

PERMANENT_TEST_IP = (
    "192.0.2.99"
)


# ============================================================
# CREATE MANAGERS
# ============================================================

isolation_manager = (
    IsolationManager()
)

traffic_manager = (
    TrafficIsolationEngine()
)

honeypot_manager = (
    HoneypotManager()
)

repeat_manager = (
    RepeatOffenderManager()
)


# ============================================================
# TEST 1
# NORMAL DEVICE RECOVERY
# ============================================================

def test_normal_device_recovery():

    print(
        "\n"
        + "=" * 75
    )

    print(
        "TEST 1: NORMAL DEVICE SELF-HEALING"
    )

    print(
        "=" * 75
    )


    # --------------------------------------------------------
    # STEP 1: Create simulated isolation
    # --------------------------------------------------------

    print(
        "\n[1] Isolating test device..."
    )


    isolation_result = (
        isolation_manager.isolate_device(

            source_ip=RECOVERY_TEST_IP,

            trust_score=40,

            behavior_risk=90,

            reason="Controlled self-healing test"
        )
    )


    print(
        isolation_result
    )


    # --------------------------------------------------------
    # STEP 2: Block traffic
    # --------------------------------------------------------

    print(
        "\n[2] Blocking traffic..."
    )


    traffic_result = (
        traffic_manager.block_device(

            source_ip=RECOVERY_TEST_IP,

            reason="Controlled self-healing test",

            trust_score=40,

            behavior_risk=90
        )
    )


    print(
        traffic_result
    )


    # --------------------------------------------------------
    # STEP 3: Deploy honeypot
    # --------------------------------------------------------

    print(
        "\n[3] Deploying honeypot..."
    )


    honeypot_result = (
        honeypot_manager.deploy_honeypot(

            source_ip=RECOVERY_TEST_IP,

            reason="Controlled self-healing test",

            service="SSH"
        )
    )


    print(
        honeypot_result
    )


    # --------------------------------------------------------
    # STEP 4: Verify isolated state
    # --------------------------------------------------------

    print(
        "\n[4] Checking isolated state..."
    )


    print(
        "Isolated:",
        isolation_manager.is_isolated(
            RECOVERY_TEST_IP
        )
    )


    print(
        "Traffic blocked:",
        traffic_manager.is_blocked(
            RECOVERY_TEST_IP
        )
    )


    print(
        "Honeypot active:",
        honeypot_manager.is_deployed(
            RECOVERY_TEST_IP
        )
    )


    # --------------------------------------------------------
    # STEP 5: Simulate threat clearance
    # --------------------------------------------------------

    print(
        "\n[5] Simulating threat clearance..."
    )


    trust_score = 90

    behavior_risk = 10


    print(
        "New Trust Score :",
        trust_score
    )


    print(
        "New Behavior Risk:",
        behavior_risk
    )


    print(
        "Threat Status   : CLEARED"
    )


    # --------------------------------------------------------
    # STEP 6: Recover
    # --------------------------------------------------------

    print(
        "\n[6] Starting self-healing..."
    )


    # Release isolation

    isolation_release = (
        isolation_manager.release_device(

            RECOVERY_TEST_IP,

            "Threat cleared - self-healing test"
        )
    )


    print(
        "Isolation:",
        isolation_release
    )


    # Release traffic block

    traffic_release = (
        traffic_manager.release_device(

            RECOVERY_TEST_IP,

            "Threat cleared - self-healing test"
        )
    )


    print(
        "Traffic:",
        traffic_release
    )


    # Stop honeypot

    honeypot_stop = (
        honeypot_manager.stop_honeypot(

            RECOVERY_TEST_IP,

            "Threat cleared - self-healing test"
        )
    )


    print(
        "Honeypot:",
        honeypot_stop
    )


    # --------------------------------------------------------
    # STEP 7: Verify recovered state
    # --------------------------------------------------------

    print(
        "\n[7] Verifying recovered state..."
    )


    isolated = (
        isolation_manager.is_isolated(
            RECOVERY_TEST_IP
        )
    )


    blocked = (
        traffic_manager.is_blocked(
            RECOVERY_TEST_IP
        )
    )


    honeypot_active = (
        honeypot_manager.is_deployed(
            RECOVERY_TEST_IP
        )
    )


    print(
        "Isolated       :",
        isolated
    )


    print(
        "Traffic Blocked:",
        blocked
    )


    print(
        "Honeypot Active:",
        honeypot_active
    )


    # --------------------------------------------------------
    # STEP 8: Result
    # --------------------------------------------------------

    if (
        not isolated
        and
        not blocked
        and
        not honeypot_active
    ):

        print(
            "\n"
            + "=" * 75
        )

        print(
            "✅ SELF-HEALING TEST PASSED"
        )

        print(
            "=" * 75
        )

        return True


    print(
        "\n"
        + "=" * 75
    )

    print(
        "❌ SELF-HEALING TEST FAILED"
    )

    print(
        "=" * 75
    )

    return False


# ============================================================
# TEST 2
# PERMANENT OFFENDER PROTECTION
# ============================================================

def test_permanent_offender_protection():

    print(
        "\n\n"
        + "=" * 75
    )

    print(
        "TEST 2: PERMANENT OFFENDER PROTECTION"
    )

    print(
        "=" * 75
    )


    # --------------------------------------------------------
    # Check repeat offender
    # --------------------------------------------------------

    offender = (
        repeat_manager.get_offender(
            PERMANENT_TEST_IP
        )
    )


    if offender is None:

        print(
            "\n❌ Permanent test offender not found."
        )

        return False


    print(
        "\nIP Address:",
        PERMANENT_TEST_IP
    )


    print(
        "Attack Count:",
        offender.get(
            "attack_count",
            0
        )
    )


    print(
        "Status:",
        offender.get(
            "status"
        )
    )


    permanent = (
        repeat_manager.is_permanently_blocked(
            PERMANENT_TEST_IP
        )
    )


    print(
        "Permanent Block:",
        permanent
    )


    # --------------------------------------------------------
    # Verify permanent status
    # --------------------------------------------------------

    if not permanent:

        print(
            "\n❌ Device is not permanently blocked."
        )

        return False


    # --------------------------------------------------------
    # Ensure isolation
    # --------------------------------------------------------

    if not isolation_manager.is_isolated(
        PERMANENT_TEST_IP
    ):

        isolation_manager.isolate_device(

            source_ip=PERMANENT_TEST_IP,

            trust_score=0,

            behavior_risk=100,

            reason="Permanent repeat offender"
        )


    # --------------------------------------------------------
    # Ensure traffic blocked
    # --------------------------------------------------------

    if not traffic_manager.is_blocked(
        PERMANENT_TEST_IP
    ):

        traffic_manager.block_device(

            source_ip=PERMANENT_TEST_IP,

            reason="Permanent repeat offender",

            trust_score=0,

            behavior_risk=100
        )


    # --------------------------------------------------------
    # Ensure honeypot active
    # --------------------------------------------------------

    if not honeypot_manager.is_deployed(
        PERMANENT_TEST_IP
    ):

        honeypot_manager.deploy_honeypot(

            source_ip=PERMANENT_TEST_IP,

            reason="Permanent repeat offender",

            service="SSH"
        )


    # --------------------------------------------------------
    # Simulate excellent trust
    # --------------------------------------------------------

    trust_score = 95

    behavior_risk = 5


    print(
        "\nSimulated Trust Score:",
        trust_score
    )


    print(
        "Simulated Behavior Risk:",
        behavior_risk
    )


    print(
        "\nAttempting automatic recovery..."
    )


    # --------------------------------------------------------
    # Permanent offenders MUST NOT recover
    # --------------------------------------------------------

    if repeat_manager.is_permanently_blocked(
        PERMANENT_TEST_IP
    ):

        print(
            "Recovery prevented."
        )

        print(
            "Reason: Permanent repeat offender."
        )


    else:

        print(
            "❌ ERROR: Recovery should have been prevented."
        )

        return False


    # --------------------------------------------------------
    # Final state
    # --------------------------------------------------------

    isolated = (
        isolation_manager.is_isolated(
            PERMANENT_TEST_IP
        )
    )


    blocked = (
        traffic_manager.is_blocked(
            PERMANENT_TEST_IP
        )
    )


    honeypot_active = (
        honeypot_manager.is_deployed(
            PERMANENT_TEST_IP
        )
    )


    print(
        "\nFinal State:"
    )


    print(
        "Isolated       :",
        isolated
    )


    print(
        "Traffic Blocked:",
        blocked
    )


    print(
        "Honeypot Active:",
        honeypot_active
    )


    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    if (
        isolated
        and
        blocked
        and
        honeypot_active
    ):

        print(
            "\n"
            + "=" * 75
        )

        print(
            "✅ PERMANENT OFFENDER PROTECTION PASSED"
        )

        print(
            "=" * 75
        )

        return True


    print(
        "\n"
        + "=" * 75
    )

    print(
        "❌ PERMANENT OFFENDER PROTECTION FAILED"
    )

    print(
        "=" * 75
    )

    return False


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "\n"
        + "=" * 80
    )

    print(
        "       SELF-HEALING ZERO TRUST INTEGRATION TEST"
    )

    print(
        "=" * 80
    )


    test1 = (
        test_normal_device_recovery()
    )


    test2 = (
        test_permanent_offender_protection()
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    print(
        "\n\n"
        + "=" * 80
    )

    print(
        "FINAL TEST SUMMARY"
    )

    print(
        "=" * 80
    )


    print(
        "Normal Device Recovery       :",
        "PASS" if test1 else "FAIL"
    )


    print(
        "Permanent Offender Protection:",
        "PASS" if test2 else "FAIL"
    )


    if test1 and test2:

        print(
            "\n"
            + "=" * 80
        )

        print(
            "✅ ALL SELF-HEALING TESTS PASSED"
        )

        print(
            "=" * 80
        )

    else:

        print(
            "\n"
            + "=" * 80
        )

        print(
            "❌ SOME SELF-HEALING TESTS FAILED"
        )

        print(
            "=" * 80
        )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()