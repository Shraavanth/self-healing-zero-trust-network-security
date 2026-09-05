"""
isolation_manager.py
--------------------
Zero Trust Isolation Manager

Responsibilities:

1. Isolate a device
2. Store isolated device information
3. Check whether a device is isolated
4. Simulate blocking access
5. Release a device after recovery
6. Maintain quarantine state

Current version:
    SAFE SIMULATION

No Windows Firewall rules are modified.
No real network device is disconnected.
"""

import json
import os
from datetime import datetime


# =====================================================
# FILE CONFIGURATION
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

ISOLATION_FILE = os.path.join(
    CURRENT_DIR,
    "isolated_devices.json"
)


# =====================================================
# ISOLATION MANAGER
# =====================================================

class IsolationManager:

    def __init__(self):

        self.isolated_devices = {}

        self.load_isolated_devices()


    # =================================================
    # LOAD ISOLATED DEVICES
    # =================================================

    def load_isolated_devices(self):

        """
        Load the current quarantine list.
        """

        if not os.path.exists(
            ISOLATION_FILE
        ):

            self.isolated_devices = {}

            return


        try:

            with open(
                ISOLATION_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)


            if isinstance(data, dict):

                self.isolated_devices = data

            else:

                self.isolated_devices = {}


        except (
            json.JSONDecodeError,
            OSError
        ):

            self.isolated_devices = {}


    # =================================================
    # SAVE ISOLATED DEVICES
    # =================================================

    def save_isolated_devices(self):

        """
        Save quarantine information.
        """

        try:

            with open(
                ISOLATION_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.isolated_devices,
                    file,
                    indent=4
                )


        except OSError as error:

            print(
                f"ERROR saving isolation data: {error}"
            )


    # =================================================
    # ISOLATE DEVICE
    # =================================================

    def isolate_device(
        self,
        source_ip,
        trust_score,
        behavior_risk,
        reason
    ):

        """
        Add a device to the quarantine list.

        If the device is already isolated,
        do not create/update the isolation record.
        """

        # ---------------------------------------------
        # CHECK IF ALREADY ISOLATED
        # ---------------------------------------------

        if self.is_isolated(
            source_ip
        ):

            existing_device = (
                self.isolated_devices[
                    source_ip
                ]
            )

            return {

                "source_ip":
                    source_ip,

                "action":
                    "ISOLATE",

                "status":
                    "ALREADY_ISOLATED",

                "message":
                    "Device is already isolated",

                "isolated_at":
                    existing_device.get(
                        "isolated_at"
                    ),

                "trust_score":
                    existing_device.get(
                        "trust_score"
                    ),

                "behavior_risk":
                    existing_device.get(
                        "behavior_risk"
                    )
            }


        # ---------------------------------------------
        # CREATE NEW ISOLATION
        # ---------------------------------------------

        timestamp = (
            datetime.now().isoformat()
        )


        self.isolated_devices[
            source_ip
        ] = {

            "source_ip":
                source_ip,

            "trust_score":
                trust_score,

            "behavior_risk":
                behavior_risk,

            "reason":
                reason,

            "isolated_at":
                timestamp,

            "status":
                "ISOLATED"
        }


        self.save_isolated_devices()


        return {

            "source_ip":
                source_ip,

            "action":
                "ISOLATE",

            "status":
                "ISOLATED",

            "message":
                "Device added to quarantine list",

            "timestamp":
                timestamp
        }


    # =================================================
    # CHECK WHETHER DEVICE IS ISOLATED
    # =================================================

    def is_isolated(
        self,
        source_ip
    ):

        """
        Return True if the device is currently
        isolated.
        """

        return (
            source_ip
            in self.isolated_devices
        )


    # =================================================
    # CHECK ACCESS
    # =================================================

    def check_access(
        self,
        source_ip
    ):

        """
        Simulate an access-control check.

        Returns:

        False → device is isolated
        True  → device is allowed
        """

        if self.is_isolated(
            source_ip
        ):

            return False

        return True


    # =================================================
    # GET DEVICE STATUS
    # =================================================

    def get_device_status(
        self,
        source_ip
    ):

        """
        Return the isolation status of one device.
        """

        if self.is_isolated(
            source_ip
        ):

            return (
                self.isolated_devices[
                    source_ip
                ]
            )


        return {

            "source_ip":
                source_ip,

            "status":
                "NOT_ISOLATED"
        }


    # =================================================
    # GET ALL ISOLATED DEVICES
    # =================================================

    def get_isolated_devices(self):

        """
        Return all currently isolated devices.
        """

        return self.isolated_devices


    # =================================================
    # RELEASE DEVICE
    # =================================================

    def release_device(
        self,
        source_ip,
        reason="Trust restored"
    ):

        """
        Remove a device from quarantine.

        This represents recovery after the device
        becomes trusted again.
        """

        if not self.is_isolated(
            source_ip
        ):

            return {

                "source_ip":
                    source_ip,

                "action":
                    "RELEASE",

                "status":
                    "NOT_ISOLATED",

                "message":
                    "Device is not currently isolated"
            }


        timestamp = (
            datetime.now().isoformat()
        )


        del self.isolated_devices[
            source_ip
        ]


        self.save_isolated_devices()


        return {

            "source_ip":
                source_ip,

            "action":
                "RELEASE",

            "status":
                "RELEASED",

            "reason":
                reason,

            "timestamp":
                timestamp,

            "message":
                "Device removed from quarantine"
        }


# =====================================================
# TEST ISOLATION MANAGER
# =====================================================

def run_tests():

    print(
        "\n" + "=" * 70
    )

    print(
        "ZERO TRUST ISOLATION MANAGER"
    )

    print(
        "=" * 70
    )

    print(
        "\nMode : SAFE SIMULATION"
    )

    print(
        "No real firewall rules will be changed."
    )


    manager = IsolationManager()


    # =================================================
    # TEST 1 — FIRST ISOLATION
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 1 : FIRST ISOLATION"
    )

    print(
        "-" * 70
    )


    result = manager.isolate_device(

        source_ip="192.0.2.40",

        trust_score=28,

        behavior_risk=100,

        reason="High behavioral risk"
    )


    print(
        f"Source IP : {result['source_ip']}"
    )

    print(
        f"Action    : {result['action']}"
    )

    print(
        f"Status    : {result['status']}"
    )

    print(
        f"Message   : {result['message']}"
    )


    # =================================================
    # TEST 2 — DUPLICATE ISOLATION
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 2 : DUPLICATE ISOLATION"
    )

    print(
        "-" * 70
    )


    result = manager.isolate_device(

        source_ip="192.0.2.40",

        trust_score=20,

        behavior_risk=100,

        reason="Another isolation request"
    )


    print(
        f"Source IP : {result['source_ip']}"
    )

    print(
        f"Action    : {result['action']}"
    )

    print(
        f"Status    : {result['status']}"
    )

    print(
        f"Message   : {result['message']}"
    )

    print(
        f"Original Trust Score : "
        f"{result.get('trust_score')}"
    )

    print(
        f"Original Behavior Risk : "
        f"{result.get('behavior_risk')}"
    )


    # =================================================
    # TEST 3 — CHECK ACCESS
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 3 : CHECK ACCESS"
    )

    print(
        "-" * 70
    )


    allowed = manager.check_access(
        "192.0.2.40"
    )


    print(
        "Access : "
        + (
            "ALLOWED"
            if allowed
            else "BLOCKED"
        )
    )


    # =================================================
    # TEST 4 — NORMAL DEVICE
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 4 : NORMAL DEVICE"
    )

    print(
        "-" * 70
    )


    allowed = manager.check_access(
        "192.0.2.10"
    )


    print(
        "Access : "
        + (
            "ALLOWED"
            if allowed
            else "BLOCKED"
        )
    )


    # =================================================
    # TEST 5 — SHOW ISOLATED DEVICES
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 5 : ISOLATED DEVICES"
    )

    print(
        "-" * 70
    )


    isolated = (
        manager.get_isolated_devices()
    )


    for ip, details in isolated.items():

        print(
            f"\nIP            : {ip}"
        )

        print(
            f"Trust Score   : "
            f"{details['trust_score']}"
        )

        print(
            f"Behavior Risk : "
            f"{details['behavior_risk']}"
        )

        print(
            f"Reason        : "
            f"{details['reason']}"
        )

        print(
            f"Status        : "
            f"{details['status']}"
        )


    # =================================================
    # TEST 6 — RELEASE
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 6 : RELEASE DEVICE"
    )

    print(
        "-" * 70
    )


    result = manager.release_device(
        "192.0.2.40",
        "Trust restored"
    )


    print(
        f"Source IP : {result['source_ip']}"
    )

    print(
        f"Action    : {result['action']}"
    )

    print(
        f"Status    : {result['status']}"
    )

    print(
        f"Message   : {result['message']}"
    )


    # =================================================
    # TEST 7 — ACCESS AFTER RELEASE
    # =================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "TEST 7 : ACCESS AFTER RELEASE"
    )

    print(
        "-" * 70
    )


    allowed = manager.check_access(
        "192.0.2.40"
    )


    print(
        "Access : "
        + (
            "ALLOWED"
            if allowed
            else "BLOCKED"
        )
    )


    print(
        "\n" + "=" * 70
    )

    print(
        "ISOLATION MANAGER TEST COMPLETED"
    )

    print(
        "=" * 70
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    run_tests()