import json
import os
from datetime import datetime


# =========================================================
# PATH CONFIGURATION
# =========================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

STATE_FILE = os.path.join(
    CURRENT_DIR,
    "repeat_offenders.json"
)


# =========================================================
# REPEAT OFFENDER MANAGER
# =========================================================

class RepeatOffenderManager:

    EXTENDED_QUARANTINE_THRESHOLD = 3
    PERMANENT_BLOCK_THRESHOLD = 4

    def __init__(self):

        self.offenders = self.load_state()


    # =====================================================
    # LOAD STATE
    # =====================================================

    def load_state(self):

        if not os.path.exists(
            STATE_FILE
        ):

            return {}

        try:

            with open(
                STATE_FILE,
                "r"
            ) as file:

                data = json.load(file)

                if isinstance(
                    data,
                    dict
                ):

                    return data

                return {}

        except (
            json.JSONDecodeError,
            OSError
        ):

            return {}


    # =====================================================
    # SAVE STATE
    # =====================================================

    def save_state(self):

        with open(
            STATE_FILE,
            "w"
        ) as file:

            json.dump(
                self.offenders,
                file,
                indent=4
            )


    # =====================================================
    # INITIALIZE HISTORICAL EVENTS
    # =====================================================

    def initialize_existing_events(
        self,
        source_ip,
        events
    ):

        """
        Mark existing historical events as processed.

        They are NOT counted as new attacks.

        This prevents old database events from causing
        an immediate permanent block when the system is
        first integrated.
        """

        if source_ip not in self.offenders:

            self.offenders[source_ip] = {

                "source_ip":
                    source_ip,

                "attack_count":
                    0,

                "first_attack":
                    None,

                "last_attack":
                    None,

                "last_attack_type":
                    None,

                "status":
                    "NORMAL",

                "processed_event_ids":
                    [],

                "initialized":
                    True
            }

        offender = (
            self.offenders[source_ip]
        )

        if "processed_event_ids" not in offender:

            offender[
                "processed_event_ids"
            ] = []


        processed_ids = set(
            offender[
                "processed_event_ids"
            ]
        )


        malicious_types = [

            "POSSIBLE_PHISHING",

            "POSSIBLE_DNS_SPOOFING",

            "POSSIBLE_ARP_SPOOFING"
        ]


        for event in events:

            attack_type = event.get(
                "attack_type"
            )

            if attack_type not in malicious_types:

                continue


            event_id = self.get_event_id(
                event
            )

            processed_ids.add(
                event_id
            )


        offender[
            "processed_event_ids"
        ] = list(
            processed_ids
        )


        self.save_state()


        return {

            "source_ip":
                source_ip,

            "status":
                "INITIALIZED",

            "message":
                "Historical events marked as processed",

            "processed_events":
                len(
                    offender[
                        "processed_event_ids"
                    ]
                )
        }


    # =====================================================
    # GET UNIQUE EVENT ID
    # =====================================================

    def get_event_id(
        self,
        event
    ):

        event_id = event.get(
            "id"
        )


        if event_id is not None:

            return str(
                event_id
            )


        return (
            str(event.get("timestamp", ""))
            + "|"
            + str(event.get("source_ip", ""))
            + "|"
            + str(event.get("attack_type", ""))
            + "|"
            + str(event.get("domain", ""))
        )


    # =====================================================
    # RECORD NEW EVENTS
    # =====================================================

    def record_new_events(
        self,
        source_ip,
        events
    ):

        """
        Process only genuinely new malicious events.

        Old events already processed are ignored.
        """

        malicious_types = [

            "POSSIBLE_PHISHING",

            "POSSIBLE_DNS_SPOOFING",

            "POSSIBLE_ARP_SPOOFING"
        ]


        if source_ip not in self.offenders:

            self.offenders[source_ip] = {

                "source_ip":
                    source_ip,

                "attack_count":
                    0,

                "first_attack":
                    None,

                "last_attack":
                    None,

                "last_attack_type":
                    None,

                "status":
                    "NORMAL",

                "processed_event_ids":
                    [],

                "initialized":
                    False
            }


        offender = (
            self.offenders[source_ip]
        )


        if "processed_event_ids" not in offender:

            offender[
                "processed_event_ids"
            ] = []


        processed_ids = set(
            offender[
                "processed_event_ids"
            ]
        )


        new_attacks = []


        for event in events:

            attack_type = event.get(
                "attack_type"
            )


            if attack_type not in malicious_types:

                continue


            event_id = self.get_event_id(
                event
            )


            if event_id in processed_ids:

                continue


            # -----------------------------------------
            # NEW ATTACK EVENT
            # -----------------------------------------

            processed_ids.add(
                event_id
            )


            offender[
                "processed_event_ids"
            ].append(
                event_id
            )


            offender[
                "attack_count"
            ] += 1


            attack_count = (
                offender[
                    "attack_count"
                ]
            )


            timestamp = event.get(
                "timestamp"
            )


            if timestamp is None:

                timestamp = (
                    datetime.now().isoformat()
                )


            if offender[
                "first_attack"
            ] is None:

                offender[
                    "first_attack"
                ] = timestamp


            offender[
                "last_attack"
            ] = timestamp


            offender[
                "last_attack_type"
            ] = attack_type


            new_attacks.append({

                "event_id":
                    event_id,

                "attack_type":
                    attack_type,

                "timestamp":
                    timestamp,

                "attack_count":
                    attack_count
            })


        # ---------------------------------------------
        # DETERMINE STATUS
        # ---------------------------------------------

        attack_count = (
            offender[
                "attack_count"
            ]
        )


        if attack_count >= self.PERMANENT_BLOCK_THRESHOLD:

            offender[
                "status"
            ] = "PERMANENT_BLOCK"


        elif attack_count >= self.EXTENDED_QUARANTINE_THRESHOLD:

            offender[
                "status"
            ] = "EXTENDED_QUARANTINE"


        elif attack_count == 2:

            offender[
                "status"
            ] = "ENHANCED_MONITORING"


        elif attack_count == 1:

            offender[
                "status"
            ] = "ACTIVE"


        elif attack_count == 0:

            offender[
                "status"
            ] = "NORMAL"


        self.save_state()


        return {

            "source_ip":
                source_ip,

            "new_attacks":
                new_attacks,

            "new_attack_count":
                len(new_attacks),

            "total_attack_count":
                attack_count,

            "status":
                offender.get(
                    "status",
                    "NORMAL"
                )
        }


    # =====================================================
    # GET OFFENDER
    # =====================================================

    def get_offender(
        self,
        source_ip
    ):

        return self.offenders.get(
            source_ip
        )


    # =====================================================
    # GET ATTACK COUNT
    # =====================================================

    def get_attack_count(
        self,
        source_ip
    ):

        offender = (
            self.get_offender(
                source_ip
            )
        )


        if not offender:

            return 0


        return offender.get(
            "attack_count",
            0
        )


    # =====================================================
    # CHECK PERMANENT BLOCK
    # =====================================================

    def is_permanently_blocked(
        self,
        source_ip
    ):

        offender = (
            self.get_offender(
                source_ip
            )
        )


        if not offender:

            return False


        return (
            offender.get("status")
            ==
            "PERMANENT_BLOCK"
        )


    # =====================================================
    # CHECK EXTENDED QUARANTINE
    # =====================================================

    def requires_extended_quarantine(
        self,
        source_ip
    ):

        offender = (
            self.get_offender(
                source_ip
            )
        )


        if not offender:

            return False


        return (
            offender.get("status")
            ==
            "EXTENDED_QUARANTINE"
        )


    # =====================================================
    # GET RESPONSE LEVEL
    # =====================================================

    def get_response_level(
        self,
        source_ip
    ):

        offender = (
            self.get_offender(
                source_ip
            )
        )


        if not offender:

            return "NORMAL"


        status = offender.get(
            "status"
        )


        if status == "PERMANENT_BLOCK":

            return "PERMANENT_BLOCK"


        if status == "EXTENDED_QUARANTINE":

            return "EXTENDED_QUARANTINE"


        if status == "ENHANCED_MONITORING":

            return "ENHANCED_MONITORING"


        if status == "ACTIVE":

            return "ISOLATE"


        return "NORMAL"


    # =====================================================
    # RELEASE PERMANENT BLOCK
    # =====================================================

    def release_permanent_block(
        self,
        source_ip,
        reason="Administrative release"
    ):

        offender = (
            self.get_offender(
                source_ip
            )
        )


        if not offender:

            return {

                "source_ip":
                    source_ip,

                "status":
                    "NOT_FOUND",

                "message":
                    "Device not found"
            }


        offender[
            "status"
        ] = "RELEASED"


        offender[
            "released_at"
        ] = (
            datetime.now().isoformat()
        )


        offender[
            "release_reason"
        ] = reason


        self.save_state()


        return {

            "source_ip":
                source_ip,

            "status":
                "RELEASED",

            "message":
                "Permanent block released",

            "reason":
                reason
        }


    # =====================================================
    # GET ALL OFFENDERS
    # =====================================================

    def get_all_offenders(self):

        return self.offenders


    # =====================================================
    # DISPLAY
    # =====================================================

    def display_offenders(self):

        print(
            "\n"
            + "=" * 80
        )

        print(
            "                  REPEAT OFFENDER STATUS"
        )

        print(
            "=" * 80
        )


        if not self.offenders:

            print(
                "No repeat offender records."
            )

            return


        for ip, data in (
            self.offenders.items()
        ):

            print(
                f"\nIP Address       : {ip}"
            )

            print(
                f"Attack Count     : "
                f"{data.get('attack_count', 0)}"
            )

            print(
                f"Last Attack      : "
                f"{data.get('last_attack')}"
            )

            print(
                f"Last Attack Type : "
                f"{data.get('last_attack_type')}"
            )

            print(
                f"Status           : "
                f"{data.get('status')}"
            )


# =========================================================
# TEST
# =========================================================

def run_tests():

    manager = (
        RepeatOffenderManager()
    )


    test_ip = "192.0.2.50"


    print(
        "\n"
        + "=" * 80
    )

    print(
        "             REPEAT OFFENDER MODULE TEST"
    )

    print(
        "=" * 80
    )


    for attack_number in range(
        1,
        5
    ):

        print(
            f"\n[ATTACK {attack_number}]"
        )


        # Simulated events for standalone test
        fake_event = {

            "id":
                f"TEST-{attack_number}",

            "timestamp":
                datetime.now().isoformat(),

            "source_ip":
                test_ip,

            "attack_type":
                "POSSIBLE_DNS_SPOOFING"
        }


        result = (
            manager.record_new_events(
                test_ip,
                [fake_event]
            )
        )


        print(
            result
        )


        print(
            "Response Level :",
            manager.get_response_level(
                test_ip
            )
        )


    print(
        "\nPermanent Block:"
    )


    print(
        manager.is_permanently_blocked(
            test_ip
        )
    )


    manager.display_offenders()


    print(
        "\nReleasing permanent block..."
    )


    print(
        manager.release_permanent_block(
            test_ip,
            reason="Administrator verified device"
        )
    )


if __name__ == "__main__":

    run_tests()