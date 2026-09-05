"""
response_logger.py
------------------
Zero Trust Response Logger

Records security response actions such as:

1. MONITOR
2. RESTRICT
3. ISOLATE
4. RELEASE

The logger maintains a historical record of
actions performed by the Zero Trust system.
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

RESPONSE_LOG_FILE = os.path.join(
    CURRENT_DIR,
    "response_logs.json"
)


# =====================================================
# RESPONSE LOGGER
# =====================================================

class ResponseLogger:

    def __init__(self):

        self.logs = []

        self.load_logs()


    # =================================================
    # LOAD EXISTING LOGS
    # =================================================

    def load_logs(self):

        """
        Load existing response history.
        """

        if not os.path.exists(
            RESPONSE_LOG_FILE
        ):

            self.logs = []

            return


        try:

            with open(
                RESPONSE_LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)


            if isinstance(data, list):

                self.logs = data

            else:

                self.logs = []


        except (
            json.JSONDecodeError,
            OSError
        ):

            self.logs = []


    # =================================================
    # SAVE LOGS
    # =================================================

    def save_logs(self):

        """
        Save response history to JSON.
        """

        try:

            with open(
                RESPONSE_LOG_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.logs,
                    file,
                    indent=4
                )


        except OSError as error:

            print(
                f"ERROR saving response logs: {error}"
            )


    # =================================================
    # LOG RESPONSE
    # =================================================

    def log_response(
        self,
        source_ip,
        action,
        status,
        trust_score=None,
        behavior_risk=None,
        reason="",
        message=""
    ):

        """
        Record one security response event.
        """

        timestamp = (
            datetime.now().isoformat()
        )


        log_entry = {

            "timestamp":
                timestamp,

            "source_ip":
                source_ip,

            "action":
                action,

            "status":
                status,

            "trust_score":
                trust_score,

            "behavior_risk":
                behavior_risk,

            "reason":
                reason,

            "message":
                message
        }


        self.logs.append(
            log_entry
        )


        self.save_logs()


        return log_entry


    # =================================================
    # GET ALL LOGS
    # =================================================

    def get_all_logs(self):

        """
        Return complete response history.
        """

        return self.logs


    # =================================================
    # GET DEVICE LOGS
    # =================================================

    def get_device_logs(
        self,
        source_ip
    ):

        """
        Return response history for
        one specific device.
        """

        return [

            log

            for log in self.logs

            if log.get("source_ip")
            == source_ip

        ]


    # =================================================
    # DISPLAY LOGS
    # =================================================

    def display_logs(self):

        """
        Display all response logs.
        """

        if not self.logs:

            print(
                "\nNo response logs found."
            )

            return


        print(
            "\n" + "=" * 100
        )

        print(
            "ZERO TRUST RESPONSE LOGS"
        )

        print(
            "=" * 100
        )


        for log in self.logs:

            print(
                "\n" + "-" * 100
            )

            print(
                f"Timestamp      : "
                f"{log.get('timestamp')}"
            )

            print(
                f"Source IP      : "
                f"{log.get('source_ip')}"
            )

            print(
                f"Action         : "
                f"{log.get('action')}"
            )

            print(
                f"Status         : "
                f"{log.get('status')}"
            )

            print(
                f"Trust Score    : "
                f"{log.get('trust_score')}"
            )

            print(
                f"Behavior Risk  : "
                f"{log.get('behavior_risk')}"
            )

            print(
                f"Reason         : "
                f"{log.get('reason')}"
            )

            print(
                f"Message        : "
                f"{log.get('message')}"
            )


        print(
            "\n" + "=" * 100
        )


# =====================================================
# TEST RESPONSE LOGGER
# =====================================================

def run_tests():

    print(
        "\n" + "=" * 70
    )

    print(
        "ZERO TRUST RESPONSE LOGGER"
    )

    print(
        "=" * 70
    )


    logger = ResponseLogger()


    # ---------------------------------------------
    # TEST 1 — ISOLATE
    # ---------------------------------------------

    print(
        "\nTEST 1 : ISOLATE RESPONSE"
    )

    result = logger.log_response(

        source_ip="192.0.2.40",

        action="ISOLATE",

        status="ISOLATED",

        trust_score=28,

        behavior_risk=100,

        reason="Behavior risk is critically high",

        message="Device isolated by Zero Trust system"
    )


    print(
        result
    )


    # ---------------------------------------------
    # TEST 2 — MONITOR
    # ---------------------------------------------

    print(
        "\nTEST 2 : MONITOR RESPONSE"
    )

    result = logger.log_response(

        source_ip="192.0.2.20",

        action="MONITOR",

        status="MONITORING",

        trust_score=70,

        behavior_risk=40,

        reason="Trust score decreased",

        message="Device placed under enhanced monitoring"
    )


    print(
        result
    )


    # ---------------------------------------------
    # TEST 3 — RELEASE
    # ---------------------------------------------

    print(
        "\nTEST 3 : RELEASE RESPONSE"
    )

    result = logger.log_response(

        source_ip="192.0.2.40",

        action="RELEASE",

        status="RELEASED",

        trust_score=85,

        behavior_risk=10,

        reason="Trust restored",

        message="Device removed from quarantine"
    )


    print(
        result
    )


    # ---------------------------------------------
    # DISPLAY LOGS
    # ---------------------------------------------

    logger.display_logs()


    print(
        "\nResponse logger test completed."
    )


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    run_tests()