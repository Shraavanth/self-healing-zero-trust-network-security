# Self-Healing Zero-Trust Network Security

A comprehensive network security monitoring and detection system that combines real-time packet analysis with advanced threat detection mechanisms. This project implements zero-trust principles by continuously monitoring network traffic and automatically detecting spoofing attacks, phishing attempts, and suspicious network behavior.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Technologies](#technologies)
- [Requirements](#requirements)

## 🎯 Project Overview

This project is designed to provide a multi-layered security monitoring platform that:
- **Captures and analyzes** network packets at multiple layers (Layer 2, Layer 3)
- **Extracts intelligent features** from network traffic for anomaly detection
- **Detects threats** including ARP spoofing, DNS spoofing, and phishing attempts
- **Stores detection data** in SQLite for historical analysis and correlation
- **Implements stateful detection** that learns network behavior and identifies deviations

## ✨ Features

### Core Capabilities
- 🔍 Real-time packet capture and analysis using Scapy
- 📊 Intelligent feature extraction from captured packets
- 🛡️ Multiple detection modules for different attack types
- 💾 SQLite database for persistent storage of events and detections
- 📝 Comprehensive logging and event tracking
- 🔐 Stateful threat detection with memory of network behavior

### Detection Modules
- **ARP Spoofing Detection**: Monitors IP-to-MAC mappings for unexpected changes
- **DNS Spoofing Detection**: Analyzes DNS responses for anomalies
- **Phishing Detection**: Analyzes domain characteristics and suspicious keywords

## 📁 Project Structure

```
self-healing-zero-trust-network-security/
├── README.md                           # Project documentation
├── requirements.txt                    # Python dependencies
│
├── packet-monitoring/                  # Module 1: Packet Capture & Analysis
│   ├── config.py                       # Configuration settings
│   ├── database.py                     # SQLite database operations
│   ├── packet_capture.py               # Main packet capture module
│   ├── packet_capture_l3.py            # Layer 3 (IP-level) capture
│   ├── packet_parser.py                # Packet parsing utilities
│   ├── packet_filter.py                # Packet filtering logic
│   ├── packet_logger.py                # Logging utilities
│   ├── feature_extractor.py            # Feature extraction from packets
│   ├── utils.py                        # Utility functions
│   ├── test_parser.py                  # Tests for packet parser
│   ├── test_feature_extractor.py       # Tests for feature extraction
│   ├── read_packetsdata_db.py          # Database query utilities
│   ├── NPCAP_INSTALLATION.md           # Npcap setup guide (Windows)
│   ├── README.md                       # Module-specific documentation
│   ├── requirements.txt                # Module dependencies
│   ├── db/                             # Database files
│   └── logs/                           # Log files
│       └── security_events.json        # Security event records
│
└── phishing-spoofing-detection/        # Module 2: Threat Detection
    ├── __init__.py
    ├── arp_spoof_detector.py           # ARP spoofing detector
    ├── dns_spoof_detector.py           # DNS spoofing detector
    ├── phishing_detector.py            # Phishing detection engine
    └── tests/
        └── test_arp_spoof_detector.py  # ARP detector tests
```

## 🔧 Modules

### Module 1: Packet Monitoring

Captures and analyzes network packets in real-time.

#### **packet_capture.py** - Main Packet Capture
- **`packet_callback(packet)`**: Callback for each captured packet
  - Logs to console, jsonfile, and database
  - Only processes IP packets
  - Parameters: `packet` (Scapy object), `log_file_handle` (file handle)

- **`start_capture()`**: Initiates packet sniffing
  - Initializes the database
  - Sets up log files
  - Captures up to `PACKET_LIMIT` packets
  - Handles Npcap errors

#### **packet_capture_l3.py** - Layer 3 Packet Capture
- **`packet_callback(packet)`**: L3-specific packet handler
  - Displays source/destination IP
  - Shows protocol number and packet length
  - Focuses on IP-level analysis

#### **feature_extractor.py** - Feature Engineering
Extracts statistical and behavioral features from packets:
- **IP Features**: Private/public IP detection
- **TTL Features**: Time-To-Live extraction (IPv4/IPv6)
- **TCP Features**: TCP flag extraction
- **ARP Features**: ARP operation type detection
- **DNS Features**: DNS query domain extraction, answer analysis
- **Protocol Features**: DNS, DNSQR, DNSRR layer detection

#### **packet_parser.py** - Packet Parsing
Parses raw packets and extracts:
- Source/destination MAC and IP addresses
- Protocol information (TCP, UDP, ICMP, ARP, DNS)
- Port numbers and packet length
- ARP and DNS specific data

#### **database.py** - Data Persistence
SQLite operations:
- **`init_database()`**: Creates required tables
- **`insert_packet(packet_data)`**: Stores captured packets
- **`insert_detection(detection_data)`**: Stores security detections
- **Query functions**: Retrieve packets and detection data

### Module 2: Phishing & Spoofing Detection

Advanced threat detection using stateful analysis.

#### **arp_spoof_detector.py** - ARP Spoofing Detection
```python
detector = ARPSpoofDetector()
detection = detector.analyze(features)
```
- Maintains IP-to-MAC address mappings
- Detects unexpected MAC address changes
- Tracks change frequency
- Severity: HIGH for suspicious changes
- Returns detection events with confidence scores

#### **dns_spoof_detector.py** - DNS Spoofing Detection
```python
detector = DNSSpoofDetector()
detection = detector.analyze(features)
```
- Tracks DNS query-to-answer mappings
- Detects changes in DNS responses
- Ignores private IP responses (baseline behavior)
- Severity: MEDIUM for suspicious changes
- Confidence based on change frequency

#### **phishing_detector.py** - Phishing Detection
```python
detector = PhishingDetector()
features = detector.extract_domain_features(domain)
is_suspicious = detector.analyze_domain(domain)
```
- Analyzes domain names and URLs for suspicious keywords
- Detects common phishing patterns (login, verify, secure, etc.)
- Analyzes query parameters for credential harvesting
- Supports multiple TLDs and homograph detection
- Severity: MEDIUM based on characteristics
- Confidence scores based on keyword matches

## 🚀 Installation

### Prerequisites
- Python 3.7+
- Windows (for Npcap) or Linux (for libpcap)
- Administrator/root privileges (for packet capture)

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd self-healing-zero-trust-network-security
```

### Step 2: Install Npcap (Windows)
1. Download from https://npcap.com/
2. Run installer with "Install Npcap in WinPcap API-compatible Mode"
3. Verify installation by running the application

See [NPCAP_INSTALLATION.md](packet-monitoring/NPCAP_INSTALLATION.md) for detailed instructions.

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation
```bash
python -c "from scapy.all import *; print('Scapy installed successfully')"
```

## ⚙️ Configuration

### Packet Monitoring Configuration
Edit `packet-monitoring/config.py`:

```python
# Network interface to monitor (Windows Npcap interface)
INTERFACE = r"\Device\NPF_{F882A092-49BF-4F87-B4CB-71721F92148D}"

# Number of packets to capture before stopping
PACKET_LIMIT = 100
```

**Note**: On Windows, find your interface with:
```bash
python -c "from scapy.all import get_windows_if_list; print(get_windows_if_list())"
```

## 📖 Usage

### Start Packet Capture
```python
from packet_monitoring.packet_capture import start_capture

# Begin monitoring network packets
start_capture()
```

### Import Security Events to Database
```python
import json
from packet_monitoring.database import insert_detection, init_database

# Create detections table
init_database()

# Read and import JSON events
with open('packet-monitoring/logs/security_events.json') as f:
    events = json.load(f)
    for event in events:
        insert_detection(event)
```

### Detect ARP Spoofing
```python
from phishing_spoofing_detection.arp_spoof_detector import ARPSpoofDetector
from packet_monitoring.feature_extractor import *

detector = ARPSpoofDetector()

# Analyze packet features
detection = detector.analyze(features)
if detection and detection.get('attack_type') == 'POSSIBLE_ARP_SPOOFING':
    print(f"Alert: {detection['message']}")
```

### Detect DNS Spoofing
```python
from phishing_spoofing_detection.dns_spoof_detector import DNSSpoofDetector

detector = DNSSpoofDetector()
detection = detector.analyze(features)
if detection and detection.get('attack_type') == 'POSSIBLE_DNS_SPOOFING':
    print(f"Alert: {detection['message']}")
```

### Detect Phishing
```python
from phishing_spoofing_detection.phishing_detector import PhishingDetector

detector = PhishingDetector()
features = detector.extract_domain_features("secure-paypal-login.com")
is_phishing = detector.analyze_domain("secure-paypal-login.com")

if is_phishing:
    print("Suspicious domain detected!")
```

## 📦 Technologies

| Technology | Purpose |
|-----------|---------|
| **Python 3.7+** | Core programming language |
| **Scapy** | Network packet manipulation and analysis |
| **SQLite3** | Lightweight database for event storage |
| **Npcap/libpcap** | Packet capture driver |
| **JSON** | Event serialization and logging |

## 📋 Requirements

See `requirements.txt` for complete dependencies. Key packages:

```
scapy>=2.4.5
```

The project uses:
- **packet-monitoring/requirements.txt**: Packet capture dependencies
- **Root requirements.txt**: Project-wide dependencies

Install with:
```bash
pip install -r requirements.txt
pip install -r packet-monitoring/requirements.txt
```

## 🔒 Security Features

- **Stateful Detection**: Learns normal network behavior and detects deviations
- **Multi-Layer Analysis**: Operates at Layers 2, 3, and Application levels
- **Zero-Trust Approach**: Continuously validates network behavior
- **Persistent Logging**: All security events logged to JSON and SQLite
- **Confidence Scoring**: Detection events include confidence and risk scores

## 📊 Detection Output Format

Security events are stored in JSON with the following structure:

```json
{
    "timestamp": "2026-08-29T15:10:09.429643",
    "attack_type": "POSSIBLE_ARP_SPOOFING",
    "source_ip": "192.168.1.1",
    "source_mac": "CC:CC:CC:CC:CC:CC",
    "domain": null,
    "severity": "HIGH",
    "confidence": 0.75,
    "risk_score": 75,
    "message": "IP-MAC mapping changed"
}
```

## 🧪 Testing

Run the included test modules:

```bash
# Test packet parser
python packet-monitoring/test_parser.py

# Test feature extractor
python packet-monitoring/test_feature_extractor.py

# Test ARP detector
python phishing-spoofing-detection/tests/test_arp_spoof_detector.py
```

## 📝 License

[Add your license here]

## 👥 Contributors

[Add contributors here]

## 📞 Support

For issues, questions, or contributions, please open an issue or submit a pull request.