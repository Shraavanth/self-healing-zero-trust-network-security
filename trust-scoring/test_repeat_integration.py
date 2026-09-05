"""
test_repeat_integration.py

Controlled integration test for the Repeat Offender system.

This script:
1. Finds the existing SQLite database containing the detections table.
2. Inserts four controlled malicious events for one test IP.
3. Sends the events to RepeatOffenderManager.
4. Verifies escalation:

   Attack 1 -> ACTIVE / ISOLATE
   Attack 2 -> ENHANCED_MONITORING
   Attack 3 -> EXTENDED_QUARANTINE
   Attack 4 -> PERMANENT_BLOCK

This is a local database simulation.
It does NOT perform a real network attack.
"""

import os
import sys
import sqlite3
from datetime import datetime


# ============================================================
# PATH CONFIGURATION
# ============================================================

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


# ============================================================
# IMPORT REPEAT OFFENDER MANAGER
# ============================================================

from repeat_offender import (
    RepeatOffenderManager
)


# ============================================================
# TEST CONFIGURATION
# ============================================================

TEST_IP = "192.0.2.99"

TEST_MAC = "AA:BB:CC:DD:EE:99"

TEST_DOMAIN = "test-repeat-offender.com"


MALICIOUS_ATTACK_TYPE = (
    "POSSIBLE_DNS_SPOOFING"
)


# ============================================================
# FIND SQLITE DATABASE
# ============================================================

def find_database():

    """
    Search the project for SQLite databases.

    The correct database is the one containing
    the 'detections' table.
    """

    print(
        "\nSearching for SQLite database..."
    )


    possible_databases = []


    # --------------------------------------------------------
    # Search project directories
    # --------------------------------------------------------

    for root, directories, files in os.walk(
        PROJECT_ROOT
    ):

        # Ignore unnecessary directories
        directories[:] = [
            directory
            for directory in directories
            if directory not in {
                ".git",
                "__pycache__",
                "node_modules",
                ".venv",
                "venv"
            }
        ]


        for filename in files:

            if filename.lower().endswith(
                ".db"
            ):

                full_path = os.path.join(
                    root,
                    filename
                )

                possible_databases.append(
                    full_path
                )


    # --------------------------------------------------------
    # Check each database
    # --------------------------------------------------------

    for database_path in possible_databases:

        try:

            connection = sqlite3.connect(
                database_path
            )

            cursor = connection.cursor()


            cursor.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                AND name='detections'
                """
            )


            result = cursor.fetchone()


            connection.close()


            if result:

                print(
                    "\nDatabase found:"
                )

                print(
                    database_path
                )

                return database_path


        except sqlite3.Error:

            continue


    # --------------------------------------------------------
    # Database not found
    # --------------------------------------------------------

    print(
        "\nERROR: Could not find a SQLite "
        "database containing the 'detections' table."
    )


    if possible_databases:

        print(
            "\nSQLite databases found:"
        )


        for database_path in possible_databases:

            print(
                " - "
                + database_path
            )


    else:

        print(
            "\nNo .db files were found "
            "inside the project."
        )


    return None


# ============================================================
# GET DETECTIONS TABLE COLUMNS
# ============================================================

def get_table_columns(
    database_file
):

    """
    Read the actual detections table schema.

    This makes the test more compatible with
    the database already used by the project.
    """

    connection = sqlite3.connect(
        database_file
    )

    cursor = connection.cursor()


    cursor.execute(
        "PRAGMA table_info(detections)"
    )


    columns = cursor.fetchall()


    connection.close()


    return [
        column[1]
        for column in columns
    ]


# ============================================================
# INSERT TEST ATTACK
# ============================================================

def insert_test_attack(
    database_file,
    attack_number
):

    """
    Insert one controlled malicious event.

    The script checks the actual database schema
    before inserting.
    """

    columns = get_table_columns(
        database_file
    )


    connection = sqlite3.connect(
        database_file
    )

    cursor = connection.cursor()


    timestamp = (
        datetime.now().isoformat()
    )


    # --------------------------------------------------------
    # Values
    # --------------------------------------------------------

    values = {}


    if "timestamp" in columns:

        values["timestamp"] = timestamp


    if "attack_type" in columns:

        values["attack_type"] = (
            MALICIOUS_ATTACK_TYPE
        )


    if "source_ip" in columns:

        values["source_ip"] = TEST_IP


    if "source_mac" in columns:

        values["source_mac"] = TEST_MAC


    if "domain" in columns:

        values["domain"] = TEST_DOMAIN


    if "severity" in columns:

        values["severity"] = "HIGH"


    if "confidence" in columns:

        values["confidence"] = 0.90


    if "risk_score" in columns:

        values["risk_score"] = 80


    if "message" in columns:

        values["message"] = (
            "Controlled repeat-offender "
            f"test attack {attack_number}"
        )


    # --------------------------------------------------------
    # Verify required fields
    # --------------------------------------------------------

    required_columns = [

        "timestamp",

        "attack_type",

        "source_ip"
    ]


    missing_columns = [

        column
        for column in required_columns
        if column not in values
    ]


    if missing_columns:

        connection.close()

        raise RuntimeError(

            "The detections table is missing "
            "required columns: "
            + str(missing_columns)
        )


    # --------------------------------------------------------
    # Build INSERT query
    # --------------------------------------------------------

    column_names = list(
        values.keys()
    )


    placeholders = ", ".join(
        ["?"] * len(column_names)
    )


    query = (
        "INSERT INTO detections "
        "("
        + ", ".join(column_names)
        + ") VALUES ("
        + placeholders
        + ")"
    )


    cursor.execute(
        query,
        [
            values[column]
            for column in column_names
        ]
    )


    connection.commit()


    # Get inserted event ID

    inserted_id = cursor.lastrowid


    connection.close()


    return inserted_id


# ============================================================
# GET TEST EVENTS
# ============================================================

def get_test_events(
    database_file
):

    """
    Read all events belonging to the test IP.
    """

    connection = sqlite3.connect(
        database_file
    )


    connection.row_factory = (
        sqlite3.Row
    )


    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT *
        FROM detections
        WHERE source_ip = ?
        ORDER BY id ASC
        """,
        (TEST_IP,)
    )


    rows = cursor.fetchall()


    connection.close()


    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# CLEAN OLD TEST EVENTS
# ============================================================

def clean_old_test_events(
    database_file
):

    """
    Delete only the previous test IP records.

    This does NOT touch real project devices.
    """

    connection = sqlite3.connect(
        database_file
    )

    cursor = connection.cursor()


    cursor.execute(
        """
        DELETE FROM detections
        WHERE source_ip = ?
        """,
        (TEST_IP,)
    )


    deleted_rows = (
        cursor.rowcount
    )


    connection.commit()

    connection.close()


    return deleted_rows


# ============================================================
# CLEAN REPEAT OFFENDER STATE
# ============================================================

def clean_repeat_offender_state(
    manager
):

    """
    Remove only the controlled test IP
    from repeat-offender state.
    """

    if manager.get_offender(
        TEST_IP
    ) is not None:

        del manager.offenders[
            TEST_IP
        ]

        manager.save_state()

        return True


    return False


# ============================================================
# TEST EXPECTED STATUS
# ============================================================

def expected_status(
    attack_number
):

    if attack_number == 1:

        return "ACTIVE"


    if attack_number == 2:

        return "ENHANCED_MONITORING"


    if attack_number == 3:

        return "EXTENDED_QUARANTINE"


    if attack_number >= 4:

        return "PERMANENT_BLOCK"


    return "NORMAL"


# ============================================================
# MAIN TEST
# ============================================================

def main():

    print(
        "\n"
        + "=" * 75
    )

    print(
        "       REPEAT OFFENDER INTEGRATION TEST"
    )

    print(
        "=" * 75
    )


    # ========================================================
    # STEP 1
    # ========================================================

    database_file = (
        find_database()
    )


    if database_file is None:

        print(
            "\nTest stopped."
        )

        sys.exit(1)


    # ========================================================
    # STEP 2
    # ========================================================

    print(
        "\nChecking detections table..."
    )


    columns = (
        get_table_columns(
            database_file
        )
    )


    print(
        "\nDetections table columns:"
    )


    for column in columns:

        print(
            " - "
            + column
        )


    # ========================================================
    # STEP 3
    # ========================================================

    manager = (
        RepeatOffenderManager()
    )


    print(
        "\nCleaning previous test state..."
    )


    deleted_events = (
        clean_old_test_events(
            database_file
        )
    )


    print(
        "Old test database events removed :",
        deleted_events
    )


    state_removed = (
        clean_repeat_offender_state(
            manager
        )
    )


    print(
        "Old repeat-offender state removed :",
        state_removed
    )


    # ========================================================
    # STEP 4
    # ========================================================

    print(
        "\n"
        + "=" * 75
    )

    print(
        "STARTING CONTROLLED ATTACK TEST"
    )

    print(
        "=" * 75
    )


    all_tests_passed = True


    # ========================================================
    # ATTACK 1 → 4
    # ========================================================

    for attack_number in range(
        1,
        5
    ):

        print(
            "\n"
            + "-" * 75
        )


        print(
            f"ADDING CONTROLLED ATTACK {attack_number}"
        )


        print(
            "-" * 75
        )


        # ----------------------------------------------------
        # Insert database event
        # ----------------------------------------------------

        event_id = (
            insert_test_attack(
                database_file,
                attack_number
            )
        )


        print(
            "Database Event ID :",
            event_id
        )


        # ----------------------------------------------------
        # Get all events
        # ----------------------------------------------------

        events = (
            get_test_events(
                database_file
            )
        )


        print(
            "Events for test IP:",
            len(events)
        )


        # ----------------------------------------------------
        # Process repeat offender
        # ----------------------------------------------------

        result = (
            manager.record_new_events(
                TEST_IP,
                events
            )
        )


        actual_count = (
            result[
                "total_attack_count"
            ]
        )


        actual_status = (
            result[
                "status"
            ]
        )


        expected = (
            expected_status(
                attack_number
            )
        )


        print(
            "\nAttack Count :",
            actual_count
        )


        print(
            "New Attacks  :",
            result[
                "new_attack_count"
            ]
        )


        print(
            "Status       :",
            actual_status
        )


        print(
            "Expected     :",
            expected
        )


        print(
            "Response     :",
            manager.get_response_level(
                TEST_IP
            )
        )


        # ----------------------------------------------------
        # Verify
        # ----------------------------------------------------

        if actual_count != attack_number:

            print(
                "\n❌ ATTACK COUNT TEST FAILED"
            )

            all_tests_passed = False


        elif actual_status != expected:

            print(
                "\n❌ STATUS TEST FAILED"
            )

            all_tests_passed = False


        else:

            print(
                "\n✅ TEST PASSED"
            )


    # ========================================================
    # FINAL VERIFICATION
    # ========================================================

    print(
        "\n"
        + "=" * 75
    )

    print(
        "FINAL RESULT"
    )

    print(
        "=" * 75
    )


    offender = (
        manager.get_offender(
            TEST_IP
        )
    )


    if offender is None:

        print(
            "\n❌ Test offender record not found."
        )

        sys.exit(1)


    final_count = (
        offender.get(
            "attack_count",
            0
        )
    )


    final_status = (
        offender.get(
            "status",
            "UNKNOWN"
        )
    )


    permanent = (
        manager.is_permanently_blocked(
            TEST_IP
        )
    )


    print(
        "\nIP Address   :",
        TEST_IP
    )


    print(
        "Attack Count :",
        final_count
    )


    print(
        "Status       :",
        final_status
    )


    print(
        "Permanent    :",
        permanent
    )


    # ========================================================
    # EXPECTED FINAL RESULT
    # ========================================================

    print(
        "\nExpected:"
    )


    print(
        "Attack 1 -> ACTIVE / ISOLATE"
    )


    print(
        "Attack 2 -> ENHANCED_MONITORING"
    )


    print(
        "Attack 3 -> EXTENDED_QUARANTINE"
    )


    print(
        "Attack 4 -> PERMANENT_BLOCK"
    )


    # ========================================================
    # FINAL PASS / FAIL
    # ========================================================

    if (
        final_count == 4
        and
        final_status == "PERMANENT_BLOCK"
        and
        permanent
        and
        all_tests_passed
    ):

        print(
            "\n"
            + "=" * 75
        )

        print(
            "✅ REPEAT OFFENDER INTEGRATION TEST PASSED"
        )

        print(
            "=" * 75
        )


    else:

        print(
            "\n"
            + "=" * 75
        )

        print(
            "❌ REPEAT OFFENDER INTEGRATION TEST FAILED"
        )

        print(
            "=" * 75
        )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()