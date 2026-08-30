import json
from database import init_database, insert_detection, DB_FILE
import sqlite3
import os

def import_security_events(json_file_path):
    """
    Import security events from JSON file into SQLite database.
    
    Args:
        json_file_path (str): Path to the security_events.json file
    """
     # Initialize database
    init_database()
    print("Database initialized.\n")
    
    # Check if the database file exists
    if not os.path.exists(DB_FILE):
        print(f"Database file '{DB_FILE}' does not exist. Please initialize the database first.")
        return
    
    # Read the JSON file
    with open(json_file_path, 'r') as f:
        events = json.load(f)
    
    # Insert each event into the database
    for event in events:
        insert_detection(event)
        print(f"Inserted: {event.get('attack_type', 'INFO')} - {event.get('message')}")
    
    print(f"\nTotal events imported: {len(events)}")

# Usage
if __name__ == "__main__":
    json_path = os.path.join(
        os.path.dirname(__file__),
        "C:\\Users\\shiva\\WorkArea\\Official\\Projects\\github_repos\\self-healing-zero-trust-network-security\\packet-monitoring\\logs\\security_events.json"
    )
    import_security_events(json_path)