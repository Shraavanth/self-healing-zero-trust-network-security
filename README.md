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
- [Database Functions Reference](#database-functions-reference)
- [Technologies](#technologies)
- [Requirements](#requirements)
- [Testing](#testing)

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
├── logs/                               # Project-level logs directory
│
├── packet-monitoring/                  # Module 1: Packet Capture & Analysis
│   ├── config.py                       # Configuration settings
│   ├── database.py                     # SQLite database operations
│   ├── packet_capture.py               # Main packet capture module
│   ├── packet_capture_backup.py        # Backup of packet capture
│   ├── packet_parser.py                # Packet parsing utilities
│   ├── packet_filter.py                # Packet filtering logic
│   ├── packet_logger.py                # Logging utilities
│   ├── feature_extractor.py            # Feature extraction from packets
│   ├── utils.py                        # Utility functions
│   ├── read_packetsdata_db.py          # Database query utilities
│   ├── write_security_events.py        # Security events import script
│   ├── test_parser.py                  # Tests for packet parser
│   ├── test_feature_extractor.py       # Tests for feature extraction
│   ├── test_dns_raw.py                 # DNS packet creation test
│   ├── sample_output.txt               # Sample packet capture output
│   ├── README.md                       # Module-specific documentation
│   ├── requirements.txt                # Module dependencies
│   ├── db/                             # Database files directory
│   └── logs/                           # Module-level log files
│
└── phishing-spoofing-detection/        # Module 2: Threat Detection
    ├── __init__.py
    ├── arp_spoof_detector.py           # ARP spoofing detector
    ├── dns_spoof_detector.py           # DNS spoofing detector
    ├── phishing_detector.py            # Phishing detection engine
    ├── detection_engine.py             # Unified detection engine
    ├── detection_event.py              # Unified event format
    ├── event_logger.py                 # Security event logger
    ├── security_statistics.py          # Detection statistics tracker
    └── tests/                          # Comprehensive test suite
        ├── test_arp_spoof_detector.py
        ├── test_dns_spoof_detector.py
        ├── test_phishing_detector.py
        ├── test_detection_engine.py
        ├── test_detection_event.py
        ├── test_event_logger.py
        ├── test_security_statistics.py
        ├── test_arp_integration.py
        ├── test_dns_integration.py
        └── test_end_to_end.py
```

## 🔧 Modules

### Module 1: Packet Monitoring

Captures and analyzes network packets in real-time with comprehensive feature extraction.

#### **packet_capture.py** - Main Packet Capture Engine
- **`packet_callback(packet, log_file_handle)`**: Callback for each captured packet
  - Logs to console, file, and database
  - Only processes IP-layer packets
  - Parameters: `packet` (Scapy object), `log_file_handle` (file handle)

- **`start_capture()`**: Initiates packet sniffing
  - Initializes the database
  - Sets up log files with headers
  - Captures up to `PACKET_LIMIT` packets
  - Handles Npcap errors gracefully

#### **packet_capture_backup.py** - Backup Implementation
Backup copy of the main packet capture module for redundancy.

#### **feature_extractor.py** - Feature Engineering
Extracts statistical and behavioral features from packets for analysis:
- **IP Features**: Private/public IP detection, IPv4/IPv6 handling
- **TTL Features**: Time-To-Live extraction (IPv4 TTL, IPv6 Hop Limit)
- **TCP Features**: TCP flag extraction and analysis
- **ARP Features**: ARP operation type detection
- **DNS Features**: DNS query domain extraction, answer analysis, response tracking
- **Protocol Detection**: DNS, DNSQR, DNSRR layer identification

#### **packet_parser.py** - Packet Parsing & Extraction
Parses raw packets and extracts key information:
- Source/destination MAC and IP addresses
- Protocol information (TCP, UDP, ICMP, ARP, DNS)
- Port numbers and packet length
- ARP-specific data (operation, hardware/protocol addresses)
- DNS-specific data (queries, responses, TTL)

#### **packet_filter.py** - Packet Filtering
Filters packets based on:
- Protocol type
- IP address ranges
- Port numbers
- Custom filter criteria

#### **packet_logger.py** - Logging Utilities
Handles logging of packet information to:
- Console output with formatted display
- Log files with timestamps
- Structured logging for analysis

#### **database.py** - Data Persistence
SQLite operations for both packets and detections:

**Packet Methods:**
- `init_database()` - Creates required tables
- `insert_packet(packet_data)` - Stores captured packets
- `get_packet_count()` - Get total packet count
- `get_all_packets()` - Retrieve all packets
- `get_packets_by_protocol(protocol)` - Filter by protocol
- `get_packets_by_ip(ip_address)` - Find packets by IP

**Detection Methods:**
- `insert_detection(detection_data)` - Stores security detections
- `write_security_events_to_db(detection_result_json)` - Import detection events
- `get_detection_count()` - Get total detection count
- `get_all_detections()` - Retrieve all detections
- `get_detections_by_type(attack_type)` - Filter by attack type
- `get_detections_by_severity(severity)` - Filter by severity
- `get_detections_by_source_ip(source_ip)` - Filter by source IP
- `get_detections_by_domain(domain)` - Filter by domain
- `get_recent_detections(limit)` - Get N most recent
- `get_detections_by_confidence(min, max)` - Filter by confidence
- `get_detections_by_risk_score(min, max)` - Filter by risk score
- `get_high_risk_detections(threshold)` - Get high-risk detections
- `get_detections_summary()` - Summary statistics

#### **read_packetsdata_db.py** - Database Query Utilities
Helper script for querying and analyzing stored packet data.

#### **write_security_events.py** - Security Events Import
Script to read security events from JSON and import into SQLite database.

#### **utils.py** - Utility Functions
Common utility functions used across the module.

#### **Test Files:**
- **test_parser.py** - Tests for packet parsing functionality
- **test_feature_extractor.py** - Tests for feature extraction
- **test_dns_raw.py** - Tests for DNS packet creation and parsing

### Module 2: Phishing & Spoofing Detection

Advanced multi-layer threat detection using stateful analysis and unified detection engine.

#### **detection_engine.py** - Unified Detection Engine
```python
engine = DetectionEngine()
event = engine.detect(packet_features)
```
- Orchestrates all detection modules (ARP, DNS, Phishing)
- Converts detection results to unified `DetectionEvent` format
- Combines results from multiple detectors
- Provides single interface for all threat detection

#### **detection_event.py** - Unified Event Format
Standardized event format for all detection types:
```python
event = DetectionEvent(
    attack_type="POSSIBLE_ARP_SPOOFING",
    source_ip="192.168.1.1",
    source_mac="AA:AA:AA:AA:AA:AA",
    severity="HIGH",
    confidence=0.85,
    risk_score=85,
    message="IP-MAC mapping changed"
)
```
Properties: timestamp, attack_type, source_ip, source_mac, domain, severity, confidence, risk_score, message

#### **event_logger.py** - Security Event Logger
```python
logger = EventLogger()
logger.log(detection_event)
```
- Stores `DetectionEvent` objects to JSON log file
- Default location: `project_root/logs/security_events.json`
- Supports custom log file paths
- Persistent event storage for historical analysis

#### **security_statistics.py** - Security Monitoring Statistics
```python
stats = SecurityStatistics()
stats.record_packet()
stats.record_event("ARP_SPOOFING", "HIGH")
```
Tracks:
- Total packets captured
- Event counts by type (ARP, DNS, Phishing)
- Severity distribution (HIGH, MEDIUM, INFO)
- Real-time security metrics

#### **arp_spoof_detector.py** - ARP Spoofing Detection
```python
detector = ARPSpoofDetector()
detection = detector.analyze(features)
```
- Maintains IP-to-MAC address mappings
- Detects unexpected MAC address changes
- Tracks change frequency and patterns
- Severity: HIGH for suspicious changes
- Returns detection events with confidence scores

#### **dns_spoof_detector.py** - DNS Spoofing Detection
```python
detector = DNSSpoofDetector()
detection = detector.analyze(features)
```
- Tracks DNS query-to-answer mappings
- Detects changes in DNS responses
- Distinguishes between suspicious and legitimate responses
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
- Supports multiple TLDs
- Severity: MEDIUM based on characteristics
- Confidence scores based on keyword matches

#### **Comprehensive Test Suite:**
- **test_arp_spoof_detector.py** - ARP detector unit tests
- **test_dns_spoof_detector.py** - DNS detector unit tests
- **test_phishing_detector.py** - Phishing detector unit tests
- **test_detection_engine.py** - Unified detection engine tests
- **test_detection_event.py** - Event format tests
- **test_event_logger.py** - Event logger tests
- **test_security_statistics.py** - Statistics tracking tests
- **test_arp_integration.py** - ARP detector integration tests
- **test_dns_integration.py** - DNS detector integration tests
- **test_end_to_end.py** - End-to-end system tests

## 🚀 Installation

### Prerequisites
- Python 3.7+
- Windows (for Npcap) or Linux/Mac (for libpcap)
- Administrator/root privileges (for packet capture)

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd self-healing-zero-trust-network-security
```

### Step 2: Install Npcap (Windows Only) - If required
1. Download from https://npcap.com/
2. Run the installer
3. Select "Install Npcap in WinPcap API-compatible Mode" option
4. Verify installation by checking available network interfaces

### Step 3: Install Python Dependencies
```bash
# Install root-level dependencies
pip install -r requirements.txt

# Install module-specific dependencies
pip install -r packet-monitoring/requirements.txt
```

### Step 4: Verify Installation
```bash
# Test Scapy installation
python -c "from scapy.all import *; print('Scapy installed successfully')"

# Test detection modules
python -c "from phishing_spoofing_detection.arp_spoof_detector import ARPSpoofDetector; print('Detection modules loaded')"
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

### Use Unified Detection Engine
```python
from phishing_spoofing_detection.detection_engine import DetectionEngine
from phishing_spoofing_detection.event_logger import EventLogger
from packet_monitoring.feature_extractor import *

# Initialize detection engine and logger
engine = DetectionEngine()
logger = EventLogger()

# Analyze packet features
detection_event = engine.detect(packet_features)

# Log the detection event
if detection_event:
    logger.log(detection_event)
    print(f"Detection logged: {detection_event.attack_type}")
```

### Track Security Statistics
```python
from phishing_spoofing_detection.security_statistics import SecurityStatistics

stats = SecurityStatistics()

# Record packet
stats.record_packet()

# Record detection event
stats.record_event("POSSIBLE_ARP_SPOOFING", "HIGH")

# Print statistics
print(f"Total packets: {stats.total_packets}")
print(f"Total events: {stats.total_events}")
print(f"ARP spoofing events: {stats.arp_spoofing_events}")
```

### Import Security Events to Database
```python
import json
from packet_monitoring.database import write_security_events_to_db

# Read and import JSON events from security_events.json
with open('packet-monitoring/logs/security_events.json') as f:
    events = json.load(f)
    write_security_events_to_db(events)
```

### Query Detections from Database
```python
from packet_monitoring.database import (
    get_all_detections,
    get_detections_by_severity,
    get_high_risk_detections,
    get_detections_summary,
    get_detection_count
)

# Get all detections
all_detections = get_all_detections()

# Get high-severity detections only
high_severity = get_detections_by_severity("HIGH")

# Get high-risk detections (risk score >= 70)
high_risk = get_high_risk_detections(risk_threshold=70)

# Get detection statistics
summary = get_detections_summary()
print(f"Total detections: {summary['total']}")
print(f"By type: {summary['by_type']}")
print(f"By severity: {summary['by_severity']}")

# Get detection count
total_count = get_detection_count()
print(f"Total detections in database: {total_count}")
```

### Detect ARP Spoofing
```python
from phishing_spoofing_detection.arp_spoof_detector import ARPSpoofDetector
from packet_monitoring.database import get_detections_by_type

detector = ARPSpoofDetector()

# Analyze packet features
detection = detector.analyze(features)
if detection and detection.get('attack_type') == 'POSSIBLE_ARP_SPOOFING':
    print(f"Alert: {detection['message']}")

# Query all ARP spoofing detections from database
arp_detections = get_detections_by_type('POSSIBLE_ARP_SPOOFING')
for detection in arp_detections:
    print(f"Detection: {detection['source_ip']} -> {detection['severity']}")
```

### Detect DNS Spoofing
```python
from phishing_spoofing_detection.dns_spoof_detector import DNSSpoofDetector
from packet_monitoring.database import get_detections_by_domain

detector = DNSSpoofDetector()
detection = detector.analyze(features)
if detection and detection.get('attack_type') == 'POSSIBLE_DNS_SPOOFING':
    print(f"Alert: {detection['message']}")

# Query DNS spoofing detections for specific domain
suspicious_domain = "example.com"
domain_detections = get_detections_by_domain(suspicious_domain)
for detection in domain_detections:
    print(f"Domain {detection['domain']}: {detection['severity']}")
```

### Detect Phishing
```python
from phishing_spoofing_detection.phishing_detector import PhishingDetector
from packet_monitoring.database import (
    get_detections_by_type,
    get_detections_by_confidence
)

detector = PhishingDetector()
features = detector.extract_domain_features("secure-paypal-login.com")
is_phishing = detector.analyze_domain("secure-paypal-login.com")

if is_phishing:
    print("Suspicious domain detected!")

# Query high-confidence phishing detections
phishing_detections = get_detections_by_type('POSSIBLE_PHISHING')
high_confidence = get_detections_by_confidence(min_confidence=0.7)
for detection in high_confidence:
    if detection['attack_type'] == 'POSSIBLE_PHISHING':
        print(f"Phishing alert: {detection['domain']} ({detection['confidence']*100}%)")
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

## 🗄️ Database Functions Reference

### Packet Operations
| Function | Purpose | Returns |
|----------|---------|---------|
| `get_packet_count()` | Total number of captured packets | int |
| `get_all_packets()` | All packets sorted by timestamp | list[dict] |
| `get_packets_by_protocol(protocol)` | Packets filtered by protocol | list[dict] |
| `get_packets_by_ip(ip_address)` | Packets involving specific IP | list[dict] |

### Detection Operations
| Function | Purpose | Returns |
|----------|---------|---------|
| `get_detection_count()` | Total detection count | int |
| `get_all_detections()` | All detections sorted by timestamp | list[dict] |
| `get_detections_by_type(type)` | Filter by attack type | list[dict] |
| `get_detections_by_severity(sev)` | Filter by severity level | list[dict] |
| `get_detections_by_source_ip(ip)` | Filter by source IP | list[dict] |
| `get_detections_by_domain(domain)` | Filter by domain | list[dict] |
| `get_recent_detections(limit)` | N most recent detections | list[dict] |
| `get_detections_by_confidence(min, max)` | Filter by confidence range | list[dict] |
| `get_detections_by_risk_score(min, max)` | Filter by risk score range | list[dict] |
| `get_high_risk_detections(threshold)` | Detections above risk threshold | list[dict] |
| `get_detections_summary()` | Summary stats by type/severity | dict |

## 🧪 Testing

### Packet Monitoring Tests
```bash
# Test packet parser
python packet-monitoring/test_parser.py

# Test feature extractor
python packet-monitoring/test_feature_extractor.py

# Test DNS raw packet creation
python packet-monitoring/test_dns_raw.py
```

### Detection Module Unit Tests
```bash
# Run all unit tests
python -m pytest phishing-spoofing-detection/tests/

# Run specific test files
python phishing-spoofing-detection/tests/test_arp_spoof_detector.py
python phishing-spoofing-detection/tests/test_dns_spoof_detector.py
python phishing-spoofing-detection/tests/test_phishing_detector.py
python phishing-spoofing-detection/tests/test_detection_engine.py
python phishing-spoofing-detection/tests/test_detection_event.py
python phishing-spoofing-detection/tests/test_event_logger.py
python phishing-spoofing-detection/tests/test_security_statistics.py
```

### Integration Tests
```bash
# ARP detector integration tests
python phishing-spoofing-detection/tests/test_arp_integration.py

# DNS detector integration tests
python phishing-spoofing-detection/tests/test_dns_integration.py

# End-to-end system tests
python phishing-spoofing-detection/tests/test_end_to_end.py
```

## 📝 License

[Add your license here]

## 👥 Contributors

[Add contributors here]

## 📞 Support

For issues, questions, or contributions, please open an issue or submit a pull request.