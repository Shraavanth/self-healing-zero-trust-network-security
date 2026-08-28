import datetime
import requests
from database import get_db_connection

# Abrar's honeypot & isolation service endpoint
ABRAR_MODULE_URL = "http://localhost:5002/api/isolate"
ABRAR_RESTORE_URL = "http://localhost:5002/api/restore"

class ZeroTrustEngine:
    """
    Dynamic Zero-Trust Scoring Engine:
    - Calculates risk-adjusted trust scores based on detected threats.
    - Applies tiered access policies (TRUSTED, MONITORED, ISOLATED).
    - Dispatches isolation commands to Abrar's honeypot module.
    - Handles self-healing score restoration.
    """

    # Configurable penalty scores per threat type
    PENALTIES = {
        "ARP_SPOOF": 45,
        "IP_SPOOF": 40,
        "PHISHING_REQUEST": 35,
        "DNS_ANOMALY": 30,
        "PORT_SCAN": 20,
        "SUSPICIOUS_BEHAVIOR": 15
    }

    # Threshold definitions
    THRESHOLD_ISOLATION = 30
    THRESHOLD_MONITORED = 70

    def __init__(self, abrar_url=ABRAR_MODULE_URL, restore_url=ABRAR_RESTORE_URL):
        self.abrar_url = abrar_url
        self.restore_url = restore_url

    def get_or_create_device(self, ip_address, mac_address="UNKNOWN"):
        """Fetches device record or initializes a new device at 100 trust score."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
        device = cursor.fetchone()

        if not device:
            cursor.execute("""
                INSERT INTO devices (ip_address, mac_address, trust_score, status, last_updated)
                VALUES (?, ?, 100, 'TRUSTED', datetime('now', 'localtime'))
            """, (ip_address, mac_address))
            conn.commit()
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            device = cursor.fetchone()

        conn.close()
        return dict(device)

    def calculate_status(self, score):
        """Determines the zero-trust tier according to score boundaries."""
        if score < self.THRESHOLD_ISOLATION:
            return "ISOLATED"
        elif score < self.THRESHOLD_MONITORED:
            return "MONITORED"
        return "TRUSTED"

    def process_threat(self, ip_address, mac_address, attack_type):
        """
        Processes an attack alert received from Shraavanth's sniffer.
        Applies penalty, updates state, logs audit trails, and triggers isolation if needed.
        """
        device = self.get_or_create_device(ip_address, mac_address)
        current_score = device["trust_score"]
        old_status = device["status"]

        # Calculate penalty and new score
        penalty = self.PENALTIES.get(attack_type.upper(), 15)
        new_score = max(0, current_score - penalty)
        new_status = self.calculate_status(new_score)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update device state
        cursor.execute("""
            UPDATE devices
            SET mac_address = ?,
                trust_score = ?,
                status = ?,
                last_updated = datetime('now', 'localtime')
            WHERE ip_address = ?
        """, (mac_address, new_score, new_status, ip_address))

        # Log security event (attack instance)
        cursor.execute("""
            INSERT INTO security_events (ip_address, attack_type, penalty_applied, score_after, timestamp)
            VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
        """, (ip_address, attack_type, penalty, new_score))

        # Log trust change audit trail
        cursor.execute("""
            INSERT INTO trust_logs (ip_address, action, delta, final_score, timestamp)
            VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
        """, (ip_address, f"PENALTY_{attack_type}", -penalty, new_score))

        conn.commit()
        conn.close()

        # Trigger isolation if score drops into the untrusted zone
        if new_status == "ISOLATED" and old_status != "ISOLATED":
            self.trigger_containment(ip_address, mac_address, new_score, attack_type)

        return {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "attack_type": attack_type,
            "penalty": penalty,
            "old_score": current_score,
            "new_score": new_score,
            "status": new_status,
            "isolation_triggered": (new_status == "ISOLATED")
        }

    def trigger_containment(self, ip_address, mac_address, score, reason):
        """Sends an autonomous containment command to Abrar's honeypot engine."""
        payload = {
            "target_ip": ip_address,
            "target_mac": mac_address,
            "trust_score": score,
            "reason": reason,
            "action": "DEPLOY_HONEYPOT_AND_ISOLATE",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            response = requests.post(self.abrar_url, json=payload, timeout=2)
            print(f"[!] ISOLATION SENT -> IP: {ip_address} | Status: {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"[!] ALERT: Failed to reach Abrar's isolation module at {self.abrar_url}. Ensure service is active.")

    def trigger_restoration(self, ip_address, mac_address, score):
        """Notifies Abrar's module to tear down honeypot routing and restore normal traffic."""
        payload = {
            "target_ip": ip_address,
            "target_mac": mac_address,
            "trust_score": score,
            "action": "RESTORE_NORMAL_TRAFFIC",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            response = requests.post(self.restore_url, json=payload, timeout=2)
            print(f"[+] RESTORE SENT -> IP: {ip_address} | Status: {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"[!] ALERT: Failed to reach Abrar's restore module at {self.restore_url}.")

    def perform_self_healing(self, recovery_increment=5, cooldown_seconds=30):
        """
        Gradually increases trust scores for non-offending devices.
        Called on interval by the background scheduler.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        # Find devices below 100 that haven't triggered an attack within the cooldown window
        cursor.execute("""
            SELECT d.ip_address, d.mac_address, d.trust_score, d.status
            FROM devices d
            WHERE d.trust_score < 100
            AND d.ip_address NOT IN (
                SELECT DISTINCT ip_address 
                FROM security_events 
                WHERE timestamp >= datetime('now', 'localtime', ?)
            )
        """, (f"-{cooldown_seconds} seconds",))

        eligible_devices = cursor.fetchall()

        for dev in eligible_devices:
            ip = dev["ip_address"]
            mac = dev["mac_address"]
            old_score = dev["trust_score"]
            old_status = dev["status"]

            new_score = min(100, old_score + recovery_increment)
            new_status = self.calculate_status(new_score)

            cursor.execute("""
                UPDATE devices
                SET trust_score = ?,
                    status = ?,
                    last_updated = datetime('now', 'localtime')
                WHERE ip_address = ?
            """, (new_score, new_status, ip))

            cursor.execute("""
                INSERT INTO trust_logs (ip_address, action, delta, final_score, timestamp)
                VALUES (?, 'SELF_HEALING_RECOVERY', ?, ?, datetime('now', 'localtime'))
            """, (ip, recovery_increment, new_score))

            # Lift isolation if device recovered past the isolation threshold
            if old_status == "ISOLATED" and new_status != "ISOLATED":
                self.trigger_restoration(ip, mac, new_score)

        conn.commit()
        conn.close()


if __name__ == "__main__":
    # Standalone verification test
    engine = ZeroTrustEngine()
    test_ip = "192.168.1.55"
    test_mac = "AA:BB:CC:DD:EE:FF"

    print("\n--- 1. Simulating ARP Spoof Attack ---")
    result1 = engine.process_threat(test_ip, test_mac, "ARP_SPOOF")
    print(f"Result: New Score = {result1['new_score']}, Status = {result1['status']}")

    print("\n--- 2. Simulating Second Attack (Phishing Request) ---")
    result2 = engine.process_threat(test_ip, test_mac, "PHISHING_REQUEST")
    print(f"Result: New Score = {result2['new_score']}, Status = {result2['status']}")

    print("\n--- 3. Testing Self-Healing Recovery Step ---")
    engine.perform_self_healing(recovery_increment=10, cooldown_seconds=0)
    dev = engine.get_or_create_device(test_ip)
    print(f"Result after healing: Score = {dev['trust_score']}, Status = {dev['status']}\n")