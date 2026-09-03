from flask import Flask, request, jsonify

from isolation import (
    isolate_device,
    restore_device,
    is_device_isolated,
    get_isolated_devices
)

from honeypot import (
    start_honeypot,
    stop_honeypot,
    is_honeypot_running
)

app = Flask(__name__)


@app.route("/api/isolate", methods=["POST"])
def isolate():
    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "No JSON data received"
        }), 400

    target_ip = data.get("target_ip")
    target_mac = data.get("target_mac")
    trust_score = data.get("trust_score")
    reason = data.get("reason")

    if not target_ip:
        return jsonify({
            "status": "error",
            "message": "target_ip is required"
        }), 400

    # Isolate the suspicious device
    isolation_success = isolate_device(
        target_ip,
        target_mac,
        reason
    )

    # Start honeypot
    honeypot_started = start_honeypot()

    print("\n[SECURITY ACTION COMPLETED]")
    print(f"Target IP: {target_ip}")
    print(f"Trust Score: {trust_score}")
    print(f"Isolation: {isolation_success}")
    print(f"Honeypot: {honeypot_started}")

    return jsonify({
        "status": "success",
        "message": "Device isolated and honeypot activated",
        "target_ip": target_ip,
        "trust_score": trust_score,
        "isolated": isolation_success,
        "honeypot_running": is_honeypot_running()
    }), 200


@app.route("/api/restore", methods=["POST"])
def restore():
    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "No JSON data received"
        }), 400

    target_ip = data.get("target_ip")

    if not target_ip:
        return jsonify({
            "status": "error",
            "message": "target_ip is required"
        }), 400

    # Restore the device
    restored = restore_device(target_ip)

    # Stop honeypot
    honeypot_stopped = stop_honeypot()

    print("\n[RECOVERY ACTION COMPLETED]")
    print(f"Target IP: {target_ip}")
    print(f"Device restored: {restored}")
    print(f"Honeypot stopped: {honeypot_stopped}")

    return jsonify({
        "status": "success",
        "message": "Device restored and honeypot stopped",
        "target_ip": target_ip,
        "restored": restored,
        "honeypot_running": is_honeypot_running()
    }), 200


@app.route("/api/status/<ip_address>", methods=["GET"])
def device_status(ip_address):
    return jsonify({
        "ip_address": ip_address,
        "isolated": is_device_isolated(ip_address)
    }), 200


@app.route("/api/isolated-devices", methods=["GET"])
def isolated_devices():
    return jsonify({
        "status": "success",
        "devices": get_isolated_devices()
    }), 200


@app.route("/api/honeypot-status", methods=["GET"])
def honeypot_status():
    return jsonify({
        "status": "success",
        "honeypot_running": is_honeypot_running()
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "service": "Abrar Security Service"
    }), 200


if __name__ == "__main__":
    print("Abrar Security Service starting on port 5002...")

    app.run(
        host="0.0.0.0",
        port=5002,
        debug=True
    )