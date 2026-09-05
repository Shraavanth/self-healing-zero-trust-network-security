"""
zero_trust_engine.py
--------------------

Integrated Self-Healing Zero Trust Network Security Engine

Modules:
1. Security Event History
2. Dynamic Trust Score
3. Behavior Risk
4. Zero Trust Policy
5. Access Decision
6. Device Isolation
7. Traffic Isolation
8. Honeypot Deployment
9. Honeypot Traffic Redirection
10. Repeat Offender Detection
11. Response Logging
12. Self-Healing / Recovery

SAFE SIMULATION:
- No real firewall rules are modified.
- No real device is disconnected.
- Traffic blocking is simulated using JSON state.
- Honeypot is simulated.
"""

import os
import sys


# ============================================================
# PATH SETUP
# ============================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.dirname(
    CURRENT_DIR
)


# ============================================================
# PACKET MONITORING PATH
# ============================================================

PACKET_MONITORING_DIR = os.path.join(
    PROJECT_ROOT,
    "packet-monitoring"
)

if PACKET_MONITORING_DIR not in sys.path:
    sys.path.insert(
        0,
        PACKET_MONITORING_DIR
    )


# ============================================================
# HONEYPOT PATH
# ============================================================

HONEYPOT_DIR = os.path.join(
    PROJECT_ROOT,
    "honeypot"
)

if HONEYPOT_DIR not in sys.path:
    sys.path.insert(
        0,
        HONEYPOT_DIR
    )


# ============================================================
# TRAFFIC ISOLATION PATH
# ============================================================

TRAFFIC_ISOLATION_DIR = os.path.join(
    PROJECT_ROOT,
    "traffic-isolation"
)

if TRAFFIC_ISOLATION_DIR not in sys.path:
    sys.path.insert(
        0,
        TRAFFIC_ISOLATION_DIR
    )


# ============================================================
# CURRENT DIRECTORY
# ============================================================

if CURRENT_DIR not in sys.path:
    sys.path.insert(
        0,
        CURRENT_DIR
    )


# ============================================================
# IMPORT MODULES
# ============================================================

from trust_score import (
    TrustScoreCalculator,
    get_all_devices
)

from behavior_monitor import (
    BehaviorMonitor
)

from policy_engine import (
    PolicyEngine
)

from access_decision import (
    AccessDecision
)

from isolation_manager import (
    IsolationManager
)

from response_logger import (
    ResponseLogger
)

from honeypot import (
    HoneypotManager
)

from traffic_isolation import (
    TrafficIsolationEngine
)

from repeat_offender import (
    RepeatOffenderManager
)


# ============================================================
# ZERO TRUST ENGINE
# ============================================================

class ZeroTrustEngine:

    def __init__(self):

        # ----------------------------------------------------
        # Trust Score
        # ----------------------------------------------------

        self.trust_calculator = (
            TrustScoreCalculator()
        )

        # ----------------------------------------------------
        # Behavior Monitor
        # ----------------------------------------------------

        self.behavior_monitor = (
            BehaviorMonitor()
        )

        # ----------------------------------------------------
        # Policy Engine
        # ----------------------------------------------------

        self.policy_engine = (
            PolicyEngine()
        )

        # ----------------------------------------------------
        # Access Decision
        # ----------------------------------------------------

        self.access_decision = (
            AccessDecision()
        )

        # ----------------------------------------------------
        # Device Isolation
        # ----------------------------------------------------

        self.isolation_manager = (
            IsolationManager()
        )

        # ----------------------------------------------------
        # Traffic Isolation
        # ----------------------------------------------------

        self.traffic_isolation = (
            TrafficIsolationEngine()
        )

        # ----------------------------------------------------
        # Honeypot
        # ----------------------------------------------------

        self.honeypot_manager = (
            HoneypotManager()
        )

        # ----------------------------------------------------
        # Response Logger
        # ----------------------------------------------------

        self.response_logger = (
            ResponseLogger()
        )

        # ----------------------------------------------------
        # Repeat Offender
        # ----------------------------------------------------

        self.repeat_offender = (
            RepeatOffenderManager()
        )


    # ========================================================
    # EVALUATE ONE DEVICE
    # ========================================================

    def evaluate_device(
        self,
        source_ip
    ):

        """
        Complete Zero Trust evaluation.

        Flow:

        Security Events
              ↓
        Trust Score
              ↓
        Behavior Risk
              ↓
        Repeat Offender Check
              ↓
        Policy Engine
              ↓
        Access Decision
              ↓
        ┌───────────────┐
        │               │
        ALLOW        ISOLATE
                        ↓
                 Device Isolation
                        ↓
                 Traffic Blocking
                        ↓
                    Honeypot
                        ↓
                  Monitoring
                        ↓
                    Recovery
        """


        # ====================================================
        # STEP 1
        # GET SECURITY EVENTS
        # ====================================================

        events = (
            self.behavior_monitor
            .get_device_events(
                source_ip
            )
        )


        # ====================================================
        # STEP 2
        # REPEAT OFFENDER ANALYSIS
        # ====================================================

        repeat_data = (
            self.repeat_offender
            .get_offender(
                source_ip
            )
        )


        # ----------------------------------------------------
        # First time seeing this device
        # ----------------------------------------------------

        if repeat_data is None:

            self.repeat_offender.initialize_existing_events(
                source_ip,
                events
            )

            repeat_result = {
                "source_ip": source_ip,
                "attack_count": 0,
                "new_attacks": 0,
                "status": "NORMAL",
                "permanent_block": False
            }

        else:

            repeat_result = (
                self.repeat_offender
                .record_new_events(
                    source_ip,
                    events
                )
            )


        # ====================================================
        # STEP 3
        # TRUST SCORE
        # ====================================================

        trust_score = (
            self.trust_calculator
            .calculate(
                events
            )
        )


        # ====================================================
        # STEP 4
        # TRUST LEVEL
        # ====================================================

        trust_level = (
            self.trust_calculator
            .get_trust_level(
                trust_score
            )
        )


        # ====================================================
        # STEP 5
        # BEHAVIOR ANALYSIS
        # ====================================================

        behavior = (
            self.behavior_monitor
            .analyze_device(
                source_ip
            )
        )


        behavior_risk = (
            behavior.get(
                "behavior_risk",
                0
            )
        )


        behavior_status = (
            behavior.get(
                "behavior_status",
                "NORMAL"
            )
        )


        # ====================================================
        # STEP 6
        # ZERO TRUST POLICY
        # ====================================================

        policy = (
            self.policy_engine
            .evaluate(
                source_ip,
                trust_score,
                behavior_risk
            )
        )


        # ====================================================
        # STEP 7
        # PERMANENT REPEAT OFFENDER OVERRIDE
        # ====================================================

        permanent_block = (
            repeat_result.get(
                "permanent_block",
                False
            )
        )

        repeat_status = (
            repeat_result.get(
                "status",
                "NORMAL"
            )
        )


        if (
            permanent_block
            or
            repeat_status == "PERMANENT_BLOCK"
        ):

            policy["decision"] = "ISOLATE"

            policy["action"] = (
                "Permanently block repeat offender"
            )

            policy["reason"] = (
                "Device exceeded the maximum "
                "allowed attack threshold"
            )


        # ====================================================
        # STEP 8
        # ACCESS DECISION
        # ====================================================

        access = (
            self.access_decision
            .decide(
                source_ip,
                trust_score,
                behavior_risk
            )
        )


        # ====================================================
        # RESPONSE
        # ====================================================

        response = None


        # ====================================================
        # ISOLATE
        # ====================================================

        if policy["decision"] == "ISOLATE":

            # ------------------------------------------------
            # DEVICE ISOLATION
            # ------------------------------------------------

            isolation_response = (
                self.isolation_manager
                .isolate_device(
                    source_ip=source_ip,
                    trust_score=trust_score,
                    behavior_risk=behavior_risk,
                    reason=policy["reason"]
                )
            )


            # ------------------------------------------------
            # TRAFFIC BLOCKING
            # ------------------------------------------------

            traffic_response = (
                self.traffic_isolation
                .block_device(
                    source_ip=source_ip,
                    reason=policy["reason"],
                    trust_score=trust_score,
                    behavior_risk=behavior_risk
                )
            )


            # ------------------------------------------------
            # HONEYPOT DEPLOYMENT
            # ------------------------------------------------

            honeypot_response = (
                self.honeypot_manager
                .deploy_honeypot(
                    source_ip=source_ip,
                    reason=policy["reason"],
                    service="SSH"
                )
            )


            # ------------------------------------------------
            # HONEYPOT REDIRECTION
            # ------------------------------------------------

            honeypot_redirect = (
                self.honeypot_manager
                .redirect_traffic(
                    source_ip=source_ip,
                    service="SSH"
                )
            )


            # ------------------------------------------------
            # STATUS
            # ------------------------------------------------

            already_isolated = (
                isolation_response.get(
                    "status"
                )
                ==
                "ALREADY_ISOLATED"
            )


            already_blocked = (
                traffic_response.get(
                    "status"
                )
                ==
                "ALREADY_BLOCKED"
            )


            already_honeypot = (
                honeypot_response.get(
                    "status"
                )
                ==
                "ALREADY_DEPLOYED"
            )


            if (
                already_isolated
                and
                already_blocked
                and
                already_honeypot
            ):

                overall_status = (
                    "ALREADY_ISOLATED"
                )

                overall_message = (
                    "Device is already isolated, "
                    "traffic is already blocked, "
                    "and honeypot is already active"
                )

            else:

                overall_status = (
                    "ISOLATED"
                )

                overall_message = (
                    "Device isolated, "
                    "traffic blocked, "
                    "and honeypot deployed"
                )


            # ------------------------------------------------
            # RESPONSE OBJECT
            # ------------------------------------------------

            response = {

                "source_ip":
                    source_ip,

                "action":
                    "ISOLATE",

                "status":
                    overall_status,

                "message":
                    overall_message,

                "isolation":
                    isolation_response,

                "traffic_isolation":
                    traffic_response,

                "honeypot":
                    honeypot_response,

                "honeypot_redirect":
                    honeypot_redirect
            }


        # ====================================================
        # ALLOW / RECOVERY
        # ====================================================

        elif policy["decision"] == "ALLOW":

            # ------------------------------------------------
            # CRITICAL:
            # PERMANENT OFFENDERS MUST NEVER AUTO-RECOVER
            # ------------------------------------------------

            if (
                permanent_block
                or
                repeat_status == "PERMANENT_BLOCK"
            ):

                # Force isolation again
                isolation_response = (
                    self.isolation_manager
                    .isolate_device(
                        source_ip=source_ip,
                        trust_score=trust_score,
                        behavior_risk=behavior_risk,
                        reason=(
                            "Permanent repeat offender "
                            "cannot be automatically recovered"
                        )
                    )
                )


                # Keep traffic blocked
                traffic_response = (
                    self.traffic_isolation
                    .block_device(
                        source_ip=source_ip,
                        reason=(
                            "Permanent repeat offender"
                        ),
                        trust_score=trust_score,
                        behavior_risk=behavior_risk
                    )
                )


                # Keep honeypot active
                honeypot_response = (
                    self.honeypot_manager
                    .deploy_honeypot(
                        source_ip=source_ip,
                        reason=(
                            "Permanent repeat offender"
                        ),
                        service="SSH"
                    )
                )


                # Keep traffic redirected
                honeypot_redirect = (
                    self.honeypot_manager
                    .redirect_traffic(
                        source_ip=source_ip,
                        service="SSH"
                    )
                )


                # Override policy
                policy["decision"] = "ISOLATE"

                policy["action"] = (
                    "Permanently block repeat offender"
                )

                policy["reason"] = (
                    "Permanent repeat offender "
                    "requires administrator release"
                )


                response = {

                    "source_ip":
                        source_ip,

                    "action":
                        "ISOLATE",

                    "status":
                        "PERMANENT_BLOCK",

                    "message":
                        (
                            "Permanent repeat offender "
                            "remains isolated. "
                            "Automatic recovery is disabled."
                        ),

                    "isolation":
                        isolation_response,

                    "traffic_isolation":
                        traffic_response,

                    "honeypot":
                        honeypot_response,

                    "honeypot_redirect":
                        honeypot_redirect
                }


            else:

                # ------------------------------------------------
                # CHECK CURRENT STATE
                # ------------------------------------------------

                was_isolated = (
                    self.isolation_manager
                    .is_isolated(
                        source_ip
                    )
                )


                was_blocked = (
                    self.traffic_isolation
                    .is_blocked(
                        source_ip
                    )
                )


                honeypot_active = (
                    self.honeypot_manager
                    .is_deployed(
                        source_ip
                    )
                )


                # ------------------------------------------------
                # RECOVERY REQUIRED
                # ------------------------------------------------

                if (
                    was_isolated
                    or
                    was_blocked
                    or
                    honeypot_active
                ):

                    # --------------------------------------------
                    # RELEASE DEVICE ISOLATION
                    # --------------------------------------------

                    isolation_response = None

                    if was_isolated:

                        isolation_response = (
                            self.isolation_manager
                            .release_device(
                                source_ip,
                                "Trust restored"
                            )
                        )


                    # --------------------------------------------
                    # RELEASE TRAFFIC BLOCK
                    # --------------------------------------------

                    traffic_response = None

                    if was_blocked:

                        traffic_response = (
                            self.traffic_isolation
                            .release_device(
                                source_ip,
                                "Threat cleared"
                            )
                        )


                    # --------------------------------------------
                    # STOP HONEYPOT
                    # --------------------------------------------

                    honeypot_response = None

                    if honeypot_active:

                        honeypot_response = (
                            self.honeypot_manager
                            .stop_honeypot(
                                source_ip,
                                (
                                    "Threat cleared and "
                                    "trust restored"
                                )
                            )
                        )


                    # --------------------------------------------
                    # RECOVERY RESPONSE
                    # --------------------------------------------

                    response = {

                        "source_ip":
                            source_ip,

                        "action":
                            "RECOVER",

                        "status":
                            "RECOVERED",

                        "message":
                            (
                                "Device recovered. "
                                "Traffic block removed, "
                                "isolation released, "
                                "and honeypot stopped."
                            ),

                        "isolation":
                            isolation_response,

                        "traffic_isolation":
                            traffic_response,

                        "honeypot":
                            honeypot_response
                    }


                else:

                    # --------------------------------------------
                    # NORMAL ALLOW
                    # --------------------------------------------

                    response = {

                        "source_ip":
                            source_ip,

                        "action":
                            "ALLOW",

                        "status":
                            "ALLOWED",

                        "message":
                            "Device has normal access"
                    }


        # ====================================================
        # MONITOR
        # ====================================================

        elif policy["decision"] == "MONITOR":

            response = {

                "source_ip":
                    source_ip,

                "action":
                    "MONITOR",

                "status":
                    "MONITORING",

                "message":
                    (
                        "Device remains under "
                        "enhanced monitoring"
                    )
            }


        # ====================================================
        # RESTRICT
        # ====================================================

        elif policy["decision"] == "RESTRICT":

            response = {

                "source_ip":
                    source_ip,

                "action":
                    "RESTRICT",

                "status":
                    "RESTRICTED",

                "message":
                    "Device access is restricted"
            }


        # ====================================================
        # RESPONSE LOGGING
        # ====================================================

        if response is not None:

            response_status = (
                response.get(
                    "status",
                    "UNKNOWN"
                )
            )


            # Do not create duplicate historical
            # entries for already existing states.

            if response_status not in [

                "ALREADY_ISOLATED",

                "ALREADY_BLOCKED",

                "ALREADY_DEPLOYED"

            ]:

                self.response_logger.log_response(

                    source_ip=source_ip,

                    action=response.get(
                        "action",
                        policy["decision"]
                    ),

                    status=response_status,

                    trust_score=trust_score,

                    behavior_risk=behavior_risk,

                    reason=policy["reason"],

                    message=response.get(
                        "message",
                        ""
                    )
                )


        # ====================================================
        # CURRENT TRAFFIC STATUS
        # ====================================================

        traffic_status = (
            self.traffic_isolation
            .check_traffic(
                source_ip
            )
        )


        # ====================================================
        # CURRENT HONEYPOT STATUS
        # ====================================================

        active_honeypot = (
            self.honeypot_manager
            .get_active_honeypots()
            .get(
                source_ip
            )
        )


        # ====================================================
        # FINAL RESULT
        # ====================================================

        return {

            "source_ip":
                source_ip,

            "event_count":
                len(events),

            "trust_score":
                trust_score,

            "trust_level":
                trust_level,

            "behavior_risk":
                behavior_risk,

            "behavior_status":
                behavior_status,

            "decision":
                policy["decision"],

            "enforcement":
                access["enforcement"],

            "action":
                policy["action"],

            "reason":
                policy["reason"],

            "message":
                access["message"],

            "response":
                response,

            "traffic_status":
                traffic_status,

            "honeypot":
                active_honeypot,

            "repeat_offender":
                repeat_result
        }


    # ========================================================
    # EVALUATE ALL DEVICES
    # ========================================================

    def evaluate_all_devices(self):

        devices = (
            get_all_devices()
        )

        results = []

        for source_ip in devices:

            result = (
                self.evaluate_device(
                    source_ip
                )
            )

            results.append(
                result
            )

        return results


# ============================================================
# DISPLAY DEVICE RESULT
# ============================================================

def display_result(result):

    print(
        "\n" + "=" * 75
    )

    print(
        "DEVICE : "
        + result["source_ip"]
    )

    print(
        "=" * 75
    )


    print(
        "Security Events : "
        + str(
            result["event_count"]
        )
    )

    print(
        "Trust Score     : "
        + str(
            result["trust_score"]
        )
    )

    print(
        "Trust Level     : "
        + result["trust_level"]
    )

    print(
        "Behavior Risk   : "
        + str(
            result["behavior_risk"]
        )
    )

    print(
        "Behavior Status : "
        + result["behavior_status"]
    )

    print(
        "Decision        : "
        + result["decision"]
    )

    print(
        "Enforcement     : "
        + result["enforcement"]
    )

    print(
        "Action          : "
        + result["action"]
    )

    print(
        "Reason          : "
        + result["reason"]
    )

    print(
        "Message         : "
        + result["message"]
    )


    # ========================================================
    # REPEAT OFFENDER
    # ========================================================

    repeat = (
        result.get(
            "repeat_offender",
            {}
        )
    )

    print(
        "\nRepeat Offender:"
    )

    print(
        "Attack Count    : "
        + str(
            repeat.get(
                "attack_count",
                0
            )
        )
    )

    print(
        "New Attacks     : "
        + str(
            repeat.get(
                "new_attacks",
                0
            )
        )
    )

    print(
        "Status          : "
        + str(
            repeat.get(
                "status",
                "NORMAL"
            )
        )
    )


    # ========================================================
    # TRAFFIC ISOLATION
    # ========================================================

    print(
        "\nTraffic Isolation:"
    )

    traffic = (
        result.get(
            "traffic_status",
            {}
        )
    )

    print(
        "Traffic Status  : "
        + str(
            traffic.get(
                "status",
                "N/A"
            )
        )
    )

    print(
        "Traffic Action  : "
        + str(
            traffic.get(
                "action",
                "N/A"
            )
        )
    )

    print(
        "Traffic Message : "
        + str(
            traffic.get(
                "message",
                "N/A"
            )
        )
    )


    # ========================================================
    # HONEYPOT
    # ========================================================

    print(
        "\nHoneypot:"
    )

    honeypot = (
        result.get(
            "honeypot"
        )
    )

    if honeypot:

        print(
            "Honeypot Status  : ACTIVE"
        )

        print(
            "Service          : "
            + str(
                honeypot.get(
                    "service",
                    "N/A"
                )
            )
        )

        print(
            "Reason           : "
            + str(
                honeypot.get(
                    "reason",
                    "N/A"
                )
            )
        )

        print(
            "Deployed At      : "
            + str(
                honeypot.get(
                    "deployed_at",
                    "N/A"
                )
            )
        )

    else:

        print(
            "Honeypot Status  : NOT ACTIVE"
        )


    # ========================================================
    # AUTOMATIC RESPONSE
    # ========================================================

    response = (
        result.get(
            "response"
        )
    )

    if response:

        print(
            "\nAutomatic Response:"
        )

        print(
            "Response Action  : "
            + str(
                response.get(
                    "action",
                    "N/A"
                )
            )
        )

        print(
            "Response Status  : "
            + str(
                response.get(
                    "status",
                    "N/A"
                )
            )
        )

        print(
            "Response Message : "
            + str(
                response.get(
                    "message",
                    "N/A"
                )
            )
        )

        # ----------------------------------------------------
        # Honeypot response
        # ----------------------------------------------------

        if response.get(
            "honeypot"
        ):

            honeypot_response = (
                response["honeypot"]
            )

            print(
                "Honeypot Action  : "
                + str(
                    honeypot_response.get(
                        "action",
                        "N/A"
                    )
                )
            )

            print(
                "Honeypot Status  : "
                + str(
                    honeypot_response.get(
                        "status",
                        "N/A"
                    )
                )
            )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "\n" + "=" * 90
    )

    print(
        "       SELF-HEALING ZERO TRUST NETWORK SECURITY ENGINE"
    )

    print(
        "=" * 90
    )


    try:

        # ----------------------------------------------------
        # CREATE ENGINE
        # ----------------------------------------------------

        engine = (
            ZeroTrustEngine()
        )


        # ----------------------------------------------------
        # EVALUATE ALL DEVICES
        # ----------------------------------------------------

        results = (
            engine.evaluate_all_devices()
        )


        # ----------------------------------------------------
        # NO DEVICES
        # ----------------------------------------------------

        if not results:

            print(
                "\nNo devices found "
                "in security database."
            )

            sys.exit(0)


        # ----------------------------------------------------
        # DISPLAY EACH DEVICE
        # ----------------------------------------------------

        for result in results:

            display_result(
                result
            )


        # ====================================================
        # ZERO TRUST SUMMARY
        # ====================================================

        print(
            "\n\n" + "=" * 90
        )

        print(
            "             ZERO TRUST SECURITY SUMMARY"
        )

        print(
            "=" * 90
        )


        print(
            f"\n"
            f"{'SOURCE IP':<20}"
            f"{'TRUST':<10}"
            f"{'BEHAVIOR':<12}"
            f"{'LEVEL':<12}"
            f"{'DECISION':<12}"
            f"{'TRAFFIC':<15}"
        )


        print(
            "-" * 90
        )


        for result in results:

            traffic = (
                result
                .get(
                    "traffic_status",
                    {}
                )
                .get(
                    "status",
                    "N/A"
                )
            )


            print(
                f"{result['source_ip']:<20}"
                f"{result['trust_score']:<10}"
                f"{result['behavior_risk']:<12}"
                f"{result['trust_level']:<12}"
                f"{result['decision']:<12}"
                f"{traffic:<15}"
            )


        # ====================================================
        # DECISION STATISTICS
        # ====================================================

        allow_count = 0
        monitor_count = 0
        restrict_count = 0
        isolate_count = 0


        for result in results:

            decision = (
                result["decision"]
            )


            if decision == "ALLOW":

                allow_count += 1


            elif decision == "MONITOR":

                monitor_count += 1


            elif decision == "RESTRICT":

                restrict_count += 1


            elif decision == "ISOLATE":

                isolate_count += 1


        print(
            "\n" + "-" * 90
        )

        print(
            "DECISION STATISTICS"
        )

        print(
            "-" * 90
        )


        print(
            "ALLOW     : "
            + str(
                allow_count
            )
        )

        print(
            "MONITOR   : "
            + str(
                monitor_count
            )
        )

        print(
            "RESTRICT  : "
            + str(
                restrict_count
            )
        )

        print(
            "ISOLATE   : "
            + str(
                isolate_count
            )
        )


        # ====================================================
        # ISOLATED DEVICES
        # ====================================================

        isolated_devices = (
            engine
            .isolation_manager
            .get_isolated_devices()
        )


        print(
            "\n" + "-" * 90
        )

        print(
            "CURRENTLY ISOLATED DEVICES"
        )

        print(
            "-" * 90
        )


        if not isolated_devices:

            print(
                "No devices are currently isolated."
            )

        else:

            for ip, details in (
                isolated_devices.items()
            ):

                print(
                    f"{ip} -> "
                    f"Trust: "
                    f"{details.get('trust_score')} | "
                    f"Behavior Risk: "
                    f"{details.get('behavior_risk')} | "
                    f"Status: "
                    f"{details.get('status')}"
                )


        # ====================================================
        # ACTIVE HONEYPOTS
        # ====================================================

        active_honeypots = (
            engine
            .honeypot_manager
            .get_active_honeypots()
        )


        print(
            "\n" + "-" * 90
        )

        print(
            "ACTIVE HONEYPOTS"
        )

        print(
            "-" * 90
        )


        if not active_honeypots:

            print(
                "No active honeypots."
            )

        else:

            for ip, details in (
                active_honeypots.items()
            ):

                print(
                    f"{ip} -> "
                    f"Service: "
                    f"{details.get('service')} | "
                    f"Status: "
                    f"{details.get('status')}"
                )


        # ====================================================
        # TRAFFIC ISOLATION RULES
        # ====================================================

        firewall_rules = (
            engine
            .traffic_isolation
            .get_all_rules()
        )


        print(
            "\n" + "-" * 90
        )

        print(
            "CURRENT TRAFFIC ISOLATION RULES"
        )

        print(
            "-" * 90
        )


        if not firewall_rules:

            print(
                "No active traffic isolation rules."
            )

        else:

            for ip, rule in (
                firewall_rules.items()
            ):

                print(
                    f"{ip} -> "
                    f"Action: "
                    f"{rule.get('action')} | "
                    f"Status: "
                    f"{rule.get('status')}"
                )


        # ====================================================
        # HONEYPOT LOGGING
        # ====================================================

        honeypot_logs = (
            engine
            .honeypot_manager
            .get_all_logs()
        )


        print(
            "\n" + "-" * 90
        )

        print(
            "HONEYPOT LOGGING"
        )

        print(
            "-" * 90
        )


        print(
            "Total Honeypot Events : "
            + str(
                len(honeypot_logs)
            )
        )


        # ====================================================
        # RESPONSE LOGGING
        # ====================================================

        response_logs = (
            engine
            .response_logger
            .get_all_logs()
        )


        print(
            "\n" + "-" * 90
        )

        print(
            "RESPONSE LOGGING"
        )

        print(
            "-" * 90
        )


        print(
            "Total Response Events : "
            + str(
                len(response_logs)
            )
        )


        # ====================================================
        # REPEAT OFFENDER SUMMARY
        # ====================================================

        print(
            "\n" + "-" * 90
        )

        print(
            "REPEAT OFFENDER SUMMARY"
        )

        print(
            "-" * 90
        )


        permanent_count = 0
        extended_count = 0
        monitoring_count = 0


        for result in results:

            repeat = (
                result.get(
                    "repeat_offender",
                    {}
                )
            )


            status = (
                repeat.get(
                    "status",
                    "NORMAL"
                )
            )


            if status == "PERMANENT_BLOCK":

                permanent_count += 1


            elif status == "EXTENDED_QUARANTINE":

                extended_count += 1


            elif status == "ENHANCED_MONITORING":

                monitoring_count += 1


        print(
            "Enhanced Monitoring : "
            + str(
                monitoring_count
            )
        )

        print(
            "Extended Quarantine : "
            + str(
                extended_count
            )
        )

        print(
            "Permanent Blocks    : "
            + str(
                permanent_count
            )
        )


        # ====================================================
        # COMPLETION
        # ====================================================

        print(
            "\n" + "=" * 90
        )

        print(
            "       SELF-HEALING ZERO TRUST EVALUATION COMPLETED"
        )

        print(
            "=" * 90
        )


    except Exception as error:

        print(
            "\n" + "=" * 70
        )

        print(
            "ERROR"
        )

        print(
            "=" * 70
        )

        print(
            error
        )


        print(
            "\nCheck that the following modules exist:"
        )

        print(
            "1. trust_score.py"
        )

        print(
            "2. behavior_monitor.py"
        )

        print(
            "3. policy_engine.py"
        )

        print(
            "4. access_decision.py"
        )

        print(
            "5. isolation_manager.py"
        )

        print(
            "6. response_logger.py"
        )

        print(
            "7. traffic_isolation.py"
        )

        print(
            "8. honeypot.py"
        )

        print(
            "9. repeat_offender.py"
        )

        print(
            "10. packet_capture.db"
        )