# Self-Healing Adaptive Zero-Trust Dynamic Scoring Engine

Module 2 of the **Self-Healing Adaptive Zero-Trust Network Security Framework for Phishing and Spoofing Attack Detection**.

This engine acts as the central policy decision and enforcement bridge. It ingests threat signals from the packet detection engine (Module 1), dynamically computes continuous trust scores, enforces tiered Zero-Trust access control boundaries, triggers autonomous honeypot isolation (Module 3), and performs background self-healing trust recovery.

---

## Architecture Overview
                   +-----------------------------------+
                  |   Module 1: Detection Engine      |
                  |   (Scapy / PyShark Packet Sniffer)|
                  +-----------------+-----------------+
                                    | HTTP POST Alerts
                                    v



            +---------------------------------------------------------------------------------+
|                        Module 2: Zero-Trust Engine (This Repo)                  |
|                                                                                 |
|   +---------------------+   +-------------------------+   +-----------------+   |
|   | /api/threat-alert   |-->| Dynamic Scoring Engine  |<--|  Self-Healing   |   |
|   | Ingestion Endpoint  |   | (Penalty Model & Rules) |   | (APScheduler)   |   |
|   +---------------------+   +------------+------------+   +-----------------+   |
|                                          |                                      |
|                                          v                                      |
|                        +-----------------+-----------------+                    |
|                        |      SQLite3 Audit Database       |                    |
|                        | (devices, events, trust_logs)     |                    |
|                        +-----------------+-----------------+                    |
|                                          |                                      |
|                     Score < 30 Threshold | Trigger                              |
+------------------------------------------+--------------------------------------+
| HTTP POST Containment Command
v
+--------------------+--------------+
|   Module 3: Containment Engine    |
| (Cowrie Honeypot + IPTables Proxy)|
+-----------------------------------+


---

## Mathematical Trust Formulation

### 1. Penalty Model
For an active node $n$, the dynamic trust score $T \in [0, 100]$ degrades instantaneously upon receiving a threat alert:

$$T_{t} = \max\Big(0,\, T_{t-1} - \sum_{i} w_i \cdot A_i\Big)$$

Where:
* $w_i$ is the static weight penalty assigned to threat type $A_i$.
* Baseline trust for new nodes: $T_{\text{init}} = 100$.

| Attack Type | Penalty ($\Delta T$) | Description |
| :--- | :--- | :--- |
| `ARP_SPOOF` | $-45$ | Layer 2 ARP cache poisoning attempt |
| `IP_SPOOF` | $-40$ | Layer 3 forged header source IP |
| `PHISHING_REQUEST` | $-35$ | Malicious domain resolution / HTTP query |
| `DNS_ANOMALY` | $-30$ | Irregular or spoofed DNS resolution query |
| `PORT_SCAN` | $-20$ | Unsolicited reconnaissance / SYN sweep |
| `SUSPICIOUS_BEHAVIOR` | $-15$ | Anomalous packet rate / unauthorized protocol |

### 2. Zero-Trust Access Policy Boundaries
* **`TRUSTED` ($70 - 100$):** Full standard access to internal network assets.
* **`MONITORED` ($30 - 69$):** Restricted bandwidth and heightened packet-level inspection.
* **`ISOLATED` ($0 - 29$):** Full access revocation. Autonomous honeypot redirection command dispatched.

### 3. Self-Healing Recovery Model
An asynchronous daemon processes nodes every $30\text{s}$. If a node exhibits zero threat flags across a cooldown window ($\tau = 45\text{s}$), trust recovers incrementally:

$$T_{t + \Delta t} = \min\big(100,\, T_t + \alpha\big)$$

Where $\alpha = 5\text{ pts}$. When a recovered score crosses $T \ge 30$, an autonomous `/api/restore` command is transmitted to lift network isolation.

---

## API Specification

### 1. Ingest Threat Alert
* **Endpoint:** `POST /api/threat-alert`
* **Content-Type:** `application/json`
* **Request Body:**
```json
{
  "source_ip": "192.168.1.188",
  "mac": "DE:AD:BE:EF:00:01",
  "attack_type": "ARP_SPOOF"
}



{
  "status": "success",
  "message": "Threat 'ARP_SPOOF' processed for 192.168.1.188",
  "data": {
    "ip_address": "192.168.1.188",
    "mac_address": "DE:AD:BE:EF:00:01",
    "attack_type": "ARP_SPOOF",
    "penalty": 45,
    "old_score": 100,
    "new_score": 55,
    "status": "MONITORED",
    "isolation_triggered": false
  }
}