import json
import os
from datetime import datetime


# ============================================================
# FILE PATHS
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

STATE_FILE = os.path.join(
    CURRENT_DIR,
    "honeypot_state.json"
)

LOG_FILE = os.path.join(
    CURRENT_DIR,
    "honeypot_logs.json"
)


# ============================================================
# HONEYPOT MANAGER
# ============================================================

class HoneypotManager:

    def __init__(self):
        self.honeypot_state = self.load_state()
        self.honeypot_logs = self.load_logs()

    # ========================================================
    # LOAD STATE
    # ========================================================

    def load_state(self):

        if not os.path.exists(STATE_FILE):
            return {}

        try:
            with open(STATE_FILE, "r") as file:
                data = json.load(file)

                if isinstance(data, dict):
                    return data

                return {}

        except (json.JSONDecodeError, OSError):
            return {}

    # ========================================================
    # SAVE STATE
    # ========================================================

    def save_state(self):

        with open(STATE_FILE, "w") as file:
            json.dump(
                self.honeypot_state,
                file,
                indent=4
            )

    # ========================================================
    # LOAD LOGS
    # ========================================================

    def load_logs(self):

        if not os.path.exists(LOG_FILE):
            return []

        try:
            with open(LOG_FILE, "r") as file:
                data = json.load(file)

                if isinstance(data, list):
                    return data

                return []

        except (json.JSONDecodeError, OSError):
            return []

    # ========================================================
    # SAVE LOGS
    # ========================================================

    def save_logs(self):

        with open(LOG_FILE, "w") as file:
            json.dump(
                self.honeypot_logs,
                file,
                indent=4
            )

    # ========================================================
    # DEPLOY HONEYPOT
    # ========================================================

    def deploy_honeypot(
        self,
        source_ip,
        reason,
        service="SSH"
    ):

        # Prevent duplicate deployment
        if self.is_deployed(source_ip):

            existing = self.honeypot_state[source_ip]

            return {
                "source_ip": source_ip,
                "action": "DEPLOY_HONEYPOT",
                "status": "ALREADY_DEPLOYED",
                "service": existing.get(
                    "service",
                    service
                ),
                "deployed_at": existing.get(
                    "deployed_at"
                ),
                "message": "Honeypot is already deployed"
            }

        timestamp = datetime.now().isoformat()

        self.honeypot_state[source_ip] = {

            "source_ip": source_ip,

            "service": service,

            "status": "ACTIVE",

            "reason": reason,

            "deployed_at": timestamp
        }

        self.save_state()

        # Log deployment
        self.log_activity(

            source_ip=source_ip,

            activity="HONEYPOT_DEPLOYED",

            service=service,

            details=reason
        )

        return {

            "source_ip": source_ip,

            "action": "DEPLOY_HONEYPOT",

            "status": "DEPLOYED",

            "service": service,

            "deployed_at": timestamp,

            "message": "Honeypot deployed successfully"
        }

    # ========================================================
    # CHECK WHETHER HONEYPOT IS ACTIVE
    # ========================================================

    def is_deployed(self, source_ip):

        if source_ip not in self.honeypot_state:
            return False

        return (
            self.honeypot_state[source_ip]
            .get("status") == "ACTIVE"
        )

    # ========================================================
    # REDIRECT TRAFFIC
    # ========================================================

    def redirect_traffic(
        self,
        source_ip,
        service="SSH"
    ):

        if not self.is_deployed(source_ip):

            return {

                "source_ip": source_ip,

                "action": "REDIRECT",

                "status": "FAILED",

                "message":
                    "Honeypot is not active"
            }

        timestamp = self.log_activity(

            source_ip=source_ip,

            activity="TRAFFIC_REDIRECTED",

            service=service,

            details=
                "Traffic redirected to "
                "simulated honeypot"
        )

        return {

            "source_ip": source_ip,

            "action": "REDIRECT",

            "status": "REDIRECTED",

            "service": service,

            "timestamp": timestamp,

            "message":
                "Traffic redirected to "
                "simulated honeypot"
        }

    # ========================================================
    # SIMULATE ATTACKER ACTIVITY
    # ========================================================

    def simulate_activity(
        self,
        source_ip,
        activity,
        service="SSH"
    ):

        if not self.is_deployed(source_ip):

            return {

                "source_ip": source_ip,

                "action": "SIMULATE_ACTIVITY",

                "status": "FAILED",

                "message":
                    "Honeypot is not active"
            }

        timestamp = self.log_activity(

            source_ip=source_ip,

            activity=activity,

            service=service,

            details=
                "Simulated attacker interaction"
        )

        return {

            "source_ip": source_ip,

            "action": "SIMULATE_ACTIVITY",

            "status": "RECORDED",

            "service": service,

            "activity": activity,

            "timestamp": timestamp
        }

    # ========================================================
    # LOG ACTIVITY
    # ========================================================

    def log_activity(
        self,
        source_ip,
        activity,
        service,
        details=""
    ):

        timestamp = datetime.now().isoformat()

        log_entry = {

            "timestamp": timestamp,

            "source_ip": source_ip,

            "service": service,

            "activity": activity,

            "details": details
        }

        self.honeypot_logs.append(log_entry)

        self.save_logs()

        return timestamp

    # ========================================================
    # GET DEVICE LOGS
    # ========================================================

    def get_device_logs(self, source_ip):

        return [

            log

            for log in self.honeypot_logs

            if log.get("source_ip") == source_ip
        ]

    # ========================================================
    # GET ALL LOGS
    # ========================================================

    def get_all_logs(self):

        return self.honeypot_logs

    # ========================================================
    # STOP HONEYPOT
    # ========================================================

    def stop_honeypot(
        self,
        source_ip,
        reason="Threat cleared"
    ):

        if not self.is_deployed(source_ip):

            return {

                "source_ip": source_ip,

                "action": "STOP_HONEYPOT",

                "status": "NOT_ACTIVE",

                "message":
                    "Honeypot is not active"
            }

        timestamp = datetime.now().isoformat()

        service = self.honeypot_state[
            source_ip
        ].get(
            "service",
            "SSH"
        )

        self.honeypot_state[
            source_ip
        ]["status"] = "STOPPED"

        self.honeypot_state[
            source_ip
        ]["stopped_at"] = timestamp

        self.honeypot_state[
            source_ip
        ]["stop_reason"] = reason

        self.save_state()

        # Log stopping
        self.log_activity(

            source_ip=source_ip,

            activity="HONEYPOT_STOPPED",

            service=service,

            details=reason
        )

        return {

            "source_ip": source_ip,

            "action": "STOP_HONEYPOT",

            "status": "STOPPED",

            "stopped_at": timestamp,

            "message":
                "Honeypot stopped"
        }

    # ========================================================
    # GET ACTIVE HONEYPOTS
    # ========================================================

    def get_active_honeypots(self):

        return {

            ip: data

            for ip, data
            in self.honeypot_state.items()

            if data.get("status") == "ACTIVE"
        }

    # ========================================================
    # DISPLAY ACTIVE HONEYPOTS
    # ========================================================

    def display_active_honeypots(self):

        active = self.get_active_honeypots()

        print("\n" + "=" * 60)
        print("              ACTIVE HONEYPOTS")
        print("=" * 60)

        if not active:

            print("No active honeypots.")

            return

        for ip, data in active.items():

            print(
                f"\nDevice IP : {ip}"
            )

            print(
                f"Service   : "
                f"{data.get('service')}"
            )

            print(
                f"Reason    : "
                f"{data.get('reason')}"
            )

            print(
                f"Deployed  : "
                f"{data.get('deployed_at')}"
            )

            print(
                f"Status    : "
                f"{data.get('status')}"
            )

    # ========================================================
    # DISPLAY LOGS
    # ========================================================

    def display_logs(self):

        print("\n" + "=" * 60)
        print("                HONEYPOT LOGS")
        print("=" * 60)

        if not self.honeypot_logs:

            print("No honeypot logs.")

            return

        for index, log in enumerate(
            self.honeypot_logs,
            start=1
        ):

            print(
                f"\n[{index}]"
            )

            print(
                f"Time     : "
                f"{log.get('timestamp')}"
            )

            print(
                f"Source IP: "
                f"{log.get('source_ip')}"
            )

            print(
                f"Service  : "
                f"{log.get('service')}"
            )

            print(
                f"Activity : "
                f"{log.get('activity')}"
            )

            print(
                f"Details  : "
                f"{log.get('details')}"
            )


# ============================================================
# TEST FUNCTION
# ============================================================

def run_tests():

    honeypot = HoneypotManager()

    test_ip = "192.0.2.40"

    print("\n")
    print("=" * 60)
    print("              HONEYPOT MODULE TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. DEPLOY
    # --------------------------------------------------------

    print("\n[1] Deploying honeypot...")

    result = honeypot.deploy_honeypot(

        source_ip=test_ip,

        reason="High behavior risk detected",

        service="SSH"
    )

    print(result)

    # --------------------------------------------------------
    # 2. REDIRECT
    # --------------------------------------------------------

    print("\n[2] Redirecting traffic...")

    result = honeypot.redirect_traffic(

        source_ip=test_ip,

        service="SSH"
    )

    print(result)

    # --------------------------------------------------------
    # 3. SIMULATE ATTACK
    # --------------------------------------------------------

    print("\n[3] Simulating attacker activity...")

    result = honeypot.simulate_activity(

        source_ip=test_ip,

        activity=
            "Multiple failed SSH login attempts",

        service="SSH"
    )

    print(result)

    # --------------------------------------------------------
    # 4. SIMULATE SECOND ACTIVITY
    # --------------------------------------------------------

    print(
        "\n[4] Simulating another "
        "attacker activity..."
    )

    result = honeypot.simulate_activity(

        source_ip=test_ip,

        activity=
            "Attempted access to /etc/passwd",

        service="SSH"
    )

    print(result)

    # --------------------------------------------------------
    # 5. DISPLAY ACTIVE HONEYPOTS
    # --------------------------------------------------------

    honeypot.display_active_honeypots()

    # --------------------------------------------------------
    # 6. DISPLAY LOGS
    # --------------------------------------------------------

    honeypot.display_logs()

    # --------------------------------------------------------
    # 7. STOP HONEYPOT
    # --------------------------------------------------------

    print("\n[5] Stopping honeypot...")

    result = honeypot.stop_honeypot(

        source_ip=test_ip,

        reason="Threat cleared"
    )

    print(result)

    # --------------------------------------------------------
    # 8. DISPLAY FINAL STATE
    # --------------------------------------------------------

    honeypot.display_active_honeypots()

    print("\n")
    print("=" * 60)
    print("              TEST COMPLETED")
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    run_tests()