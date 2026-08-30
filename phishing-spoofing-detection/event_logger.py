"""
event_logger.py
---------------
Security Event Logger

Stores DetectionEvent objects permanently
in a JSON log file.

Author : Shraavanth
"""

import os
import json


class EventLogger:

    def __init__(self, log_file=None):
        """
        Create the event logger.

        If no log file is provided, events are stored in:

        project_root/logs/security_events.json
        """

        # ---------------------------------------------
        # Find project root
        # ---------------------------------------------

        current_dir = os.path.dirname(
            os.path.abspath(__file__)
        )

        project_root = os.path.dirname(
            current_dir
        )

        # ---------------------------------------------
        # Default log location
        # ---------------------------------------------

        if log_file is None:

            log_dir = os.path.join(
                project_root,
                "logs"
            )

            os.makedirs(
                log_dir,
                exist_ok=True
            )

            log_file = os.path.join(
                log_dir,
                "security_events.json"
            )

        self.log_file = log_file

        # ---------------------------------------------
        # Create empty log file if required
        # ---------------------------------------------

        if not os.path.exists(self.log_file):

            with open(
                self.log_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    [],
                    file,
                    indent=4
                )


    # =================================================
    # LOG EVENT
    # =================================================

    def log_event(self, event):
        """
        Store a DetectionEvent in the JSON log.
        """

        # ---------------------------------------------
        # Convert DetectionEvent to dictionary
        # ---------------------------------------------

        if hasattr(event, "to_dict"):

            event_data = event.to_dict()

        elif isinstance(event, dict):

            event_data = event

        else:

            raise TypeError(
                "event must be a DetectionEvent "
                "or dictionary"
            )

        # ---------------------------------------------
        # Read existing events
        # ---------------------------------------------

        try:

            with open(
                self.log_file,
                "r",
                encoding="utf-8"
            ) as file:

                events = json.load(file)

        except (
            json.JSONDecodeError,
            FileNotFoundError
        ):

            events = []

        # ---------------------------------------------
        # Add new event
        # ---------------------------------------------

        events.append(event_data)

        # ---------------------------------------------
        # Save events
        # ---------------------------------------------

        with open(
            self.log_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                events,
                file,
                indent=4
            )


    # =================================================
    # GET ALL EVENTS
    # =================================================

    def get_events(self):
        """
        Return all stored security events.
        """

        try:

            with open(
                self.log_file,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)

        except (
            json.JSONDecodeError,
            FileNotFoundError
        ):

            return []


    # =================================================
    # CLEAR LOG
    # =================================================

    def clear_log(self):
        """
        Delete all stored security events.
        """

        with open(
            self.log_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                [],
                file,
                indent=4
            )