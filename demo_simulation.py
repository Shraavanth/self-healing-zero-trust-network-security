import time
import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def print_banner(title):
    print("\n" + "=" * 60)
    print(f" >>> {title.upper()} <<<")
    print("=" * 60)

def send_alert(ip, mac, attack_type):
    url = f"{BASE_URL}/api/threat-alert"
    payload = {
        "source_ip": ip,
        "mac": mac,
        "attack_type": attack_type
    }
    try:
        res = requests.post(url, json=payload, timeout=3)
        data = res.json().get("data", {})
        print(f"[*] ALERT SENT -> IP: {ip} | Attack: {attack_type}")
        print(f"    - Score: {data.get('old_score')} -> {data.get('new_score')} | Tier: {data.get('status')} | Isolation Triggered: {data.get('isolation_triggered')}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: Ensure app.py is running on {BASE_URL}. Error: {e}")

def get_stats():
    try:
        res = requests.get(f"{BASE_URL}/api/stats")
        stats = res.json()
        print("\n--- Current Network Metrics ---")
        print(f"Total Nodes: {stats['total_devices']} | Trusted: {stats['trusted_devices']} | Monitored: {stats['monitored_devices']} | Isolated: {stats['isolated_devices']}")
        print(f"Average Network Trust: {stats['average_trust_score']}%")
    except Exception as e:
        print(f"[!] Failed to fetch stats: {e}")

if __name__ == "__main__":
    print_banner("Zero-Trust Dynamic Engine Demo Simulation")

    # Nodes Setup
    victim_ip = "192.168.1.50"
    victim_mac = "AA:BB:CC:11:22:33"

    attacker_ip = "192.168.1.188"
    attacker_mac = "DE:AD:BE:EF:00:01"

    iot_node_ip = "192.168.1.204"
    iot_node_mac = "44:55:66:77:88:99"

    # Step 1: Initialize baseline traffic
    print("\n[Step 1] Initializing benign traffic from IoT and Client nodes...")
    send_alert(victim_ip, victim_mac, "SUSPICIOUS_BEHAVIOR") # Minor anomaly
    send_alert(iot_node_ip, iot_node_mac, "SUSPICIOUS_BEHAVIOR")
    get_stats()
    time.sleep(2)

    # Step 2: Attacker executes ARP Spoofing
    print_banner("Step 2: Injecting ARP Spoof Attack")
    print(f"Simulating attack packet intercepted by Shraavanth's sniffer from {attacker_ip}...")
    send_alert(attacker_ip, attacker_mac, "ARP_SPOOF")
    get_stats()
    time.sleep(3)

    # Step 3: Attacker launches Phishing Query (Triggering Critical Threshold)
    print_banner("Step 3: Attacker Triggers Phishing Attack -> Containment Trigger")
    send_alert(attacker_ip, attacker_mac, "PHISHING_REQUEST")
    get_stats()

    # Step 4: Self-Healing Demonstration
    print_banner("Step 4: Monitoring Self-Healing & Telemetry")
    print("[*] Attacks ceased. Waiting 40 seconds to observe background trust recovery...")
    for remaining in range(40, 0, -10):
        print(f"[*] Cooldown in progress... {remaining}s remaining")
        time.sleep(10)

    print("\n[*] Querying database post-cooldown for score recovery:")
    get_stats()
    print("\n[+] Simulation run complete. Review real-time graphs at http://127.0.0.1:5000\n")