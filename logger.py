import json
import os
from datetime import datetime


LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security_events.json")


def initialize_logger():
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as file:
            json.dump([], file, indent=4)


def log_event(event_type, details):
    initialize_logger()

    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "details": details
    }

    with open(LOG_FILE, "r") as file:
        events = json.load(file)

    events.append(event)

    with open(LOG_FILE, "w") as file:
        json.dump(events, file, indent=4)

    print(f"[LOGGED] {event_type}")


def get_events():
    initialize_logger()

    with open(LOG_FILE, "r") as file:
        return json.load(file)