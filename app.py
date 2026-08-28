from flask import Flask, request, jsonify, render_template
from apscheduler.schedulers.background import BackgroundScheduler
from trust_engine import ZeroTrustEngine
from database import get_db_connection, init_db
import atexit

app = Flask(__name__)
engine = ZeroTrustEngine()

# Initialize Database on startup
init_db()

# ==========================================
# 1. BACKGROUND SCHEDULER (Self-Healing)
# ==========================================
def self_healing_job():
    """Runs periodically to restore trust scores for clean devices."""
    try:
        # Adds +5 points every 30s to devices with no attack alerts in the last 45s
        engine.perform_self_healing(recovery_increment=5, cooldown_seconds=45)
    except Exception as e:
        print(f"[!] Error during self-healing job: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(func=self_healing_job, trigger="interval", seconds=30)
scheduler.start()

# Graceful shutdown of scheduler when Flask exits
atexit.register(lambda: scheduler.shutdown(wait=False))


# ==========================================
# 2. WEB UI ROUTE
# ==========================================
@app.route("/")
def index():
    """Renders the Real-Time Zero-Trust Monitoring Dashboard."""
    return render_template("dashboard.html")


# ==========================================
# 3. REST API ENDPOINTS
# ==========================================

@app.route("/api/threat-alert", methods=["POST"])
def receive_threat():
    """
    Ingestion endpoint for Shraavanth's sniffer engine.
    Expected JSON payload:
    {
        "source_ip": "192.168.1.105",
        "mac": "AA:BB:CC:DD:EE:FF",
        "attack_type": "ARP_SPOOF"
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON or missing body"}), 400

    source_ip = data.get("source_ip")
    mac = data.get("mac", "UNKNOWN")
    attack_type = data.get("attack_type", "SUSPICIOUS_BEHAVIOR")

    if not source_ip:
        return jsonify({"error": "Missing required field: 'source_ip'"}), 400

    # Process threat via core trust engine
    result = engine.process_threat(source_ip, mac, attack_type)

    return jsonify({
        "status": "success",
        "message": f"Threat '{attack_type}' processed for {source_ip}",
        "data": result
    }), 200


@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Returns all active network nodes and their current Zero-Trust posture."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY trust_score ASC")
    rows = cursor.fetchall()
    conn.close()

    devices = [dict(row) for row in rows]
    return jsonify({
        "total_devices": len(devices),
        "devices": devices
    }), 200


@app.route("/api/events", methods=["GET"])
def get_security_events():
    """Returns the most recent security threats detected by Shraavanth's module."""
    limit = request.args.get("limit", default=15, type=int)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    events = [dict(row) for row in rows]
    return jsonify({"events": events}), 200


@app.route("/api/logs", methods=["GET"])
def get_trust_logs():
    """Returns dynamic score adjustment audit trails (penalties and healing)."""
    limit = request.args.get("limit", default=20, type=int)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM trust_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    logs = [dict(row) for row in rows]
    return jsonify({"logs": logs}), 200


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns aggregated summary metrics for dashboard summary cards."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM devices")
    total_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'ISOLATED'")
    isolated_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'MONITORED'")
    monitored_devices = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(trust_score) FROM devices")
    avg_score_raw = cursor.fetchone()[0]
    avg_trust = round(avg_score_raw, 1) if avg_score_raw is not None else 100.0

    conn.close()

    return jsonify({
        "total_devices": total_devices,
        "isolated_devices": isolated_devices,
        "monitored_devices": monitored_devices,
        "trusted_devices": total_devices - (isolated_devices + monitored_devices),
        "average_trust_score": avg_trust
    }), 200


# ==========================================
# 4. ENTRY POINT
# ==========================================
if __name__ == "__main__":
    # Host on 0.0.0.0 so teammates can hit your API from local network or localhost
    print("[*] Starting Zero-Trust Policy Engine on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)