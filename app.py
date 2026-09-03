from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/isolate", methods=["POST"])
def isolate():
    data = request.get_json()

    print("\n[ISOLATION REQUEST RECEIVED]")
    print(f"Target IP: {data.get('target_ip')}")
    print(f"Target MAC: {data.get('target_mac')}")
    print(f"Trust Score: {data.get('trust_score')}")
    print(f"Reason: {data.get('reason')}")

    return jsonify({
        "status": "success",
        "message": "Isolation request received",
        "target_ip": data.get("target_ip")
    }), 200


@app.route("/api/restore", methods=["POST"])
def restore():
    data = request.get_json()

    print("\n[RESTORE REQUEST RECEIVED]")
    print(f"Target IP: {data.get('target_ip')}")
    print(f"Target MAC: {data.get('target_mac')}")
    print(f"Trust Score: {data.get('trust_score')}")

    return jsonify({
        "status": "success",
        "message": "Restore request received",
        "target_ip": data.get("target_ip")
    }), 200


if __name__ == "__main__":
    print("Abrar Security Service starting on port 5002...")
    app.run(host="0.0.0.0", port=5002, debug=True)