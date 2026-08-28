import sqlite3

DB_NAME = "zero_trust.db"

def get_db_connection():
    """Establishes connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates the necessary tables if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table 1: Track all network devices and their current trust scores
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT NOT NULL,
            trust_score INTEGER NOT NULL DEFAULT 100,
            status TEXT NOT NULL DEFAULT 'TRUSTED',
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 2: Track threats received from Shraavanth's sniffer
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            penalty_applied INTEGER NOT NULL,
            score_after INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ip_address) REFERENCES devices (ip_address)
        )
    """)

    # Table 3: Audit log for all score changes (penalties and healing)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trust_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            action TEXT NOT NULL,
            delta INTEGER NOT NULL,
            final_score INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized successfully: zero_trust.db")

if __name__ == "__main__":
    init_db()