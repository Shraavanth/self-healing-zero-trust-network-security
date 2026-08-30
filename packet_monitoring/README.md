# Module 1 - Packet Monitoring

## Objective

Capture network packets and extract useful information for further security analysis.

## Features

- Packet Capture
- Packet Parsing
- Packet Filtering
- Packet Logging
- Database Storage

## Technologies

- Python
- Scapy
- SQLite

---

## Methods Used in Packet-Monitoring

### 1. **packet_capture.py** - Main Packet Capture Module

#### `packet_callback(packet, log_file_handle)`
- **Purpose**: Callback function automatically called by Scapy whenever a packet is captured
- **Parameters**:
  - `packet`: Scapy packet object
  - `log_file_handle`: File handle for writing logs
- **Functionality**: Logs packet information to console, log file, and database if packet contains IP layer

#### `start_capture()`
- **Purpose**: Initiates packet sniffing with database and file logging
- **Functionality**: 
  - Initializes the database
  - Sets up log file with headers
  - Starts packet sniffing using Scapy
  - Handles errors related to Npcap installation
  - Captures up to PACKET_LIMIT number of packets

---

### 2. **packet_capture_l3.py** - Layer 3 (IP-level) Packet Capture

#### `packet_callback(packet)`
- **Purpose**: Callback function called when a packet is captured at Layer 3
- **Parameters**: `packet` - Scapy packet object
- **Functionality**: Displays basic packet information (source IP, destination IP, protocol number, packet length)

#### `start_capture()`
- **Purpose**: Initiates Layer 3 packet sniffing without requiring Npcap
- **Functionality**:
  - Configures L3socket for Layer 3 sniffing
  - Captures IP-only packets
  - Does not require Npcap installation
  - Captures up to PACKET_LIMIT number of packets

---

### 3. **packet_parser.py** - Packet Parsing Module

#### `get_protocol(packet)`
- **Purpose**: Identifies the main protocol present in a packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: Protocol name (ARP, DNS, TCP, UDP, ICMP, IP, IPv6, or UNKNOWN)
- **Functionality**: Checks packet layers in priority order to determine protocol type

#### `parse_packet(packet)`
- **Purpose**: Extracts useful information from a Scapy packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: Dictionary containing parsed packet data with keys:
  - MAC layer: `src_mac`, `dst_mac`
  - IP layer: `src_ip`, `dst_ip`
  - Transport layer: `src_port`, `dst_port`
  - Protocol: `protocol`
  - ARP-specific: `arp_src_ip`, `arp_src_mac`, `arp_dst_ip`, `arp_dst_mac`
  - General: `packet_length`
- **Functionality**: Extracts Ethernet, IPv4, IPv6, ARP, TCP, and UDP information from packet

---

### 4. **feature_extractor.py** - Feature Extraction Module

#### `is_private_ip(ip)`
- **Purpose**: Checks whether an IP address belongs to a private network
- **Parameters**: `ip` - IP address string
- **Returns**: Boolean (True/False) or None if invalid
- **Functionality**: Uses Python's `ipaddress` module to determine if IP is private

#### `get_ttl(packet)`
- **Purpose**: Extracts TTL (IPv4) or Hop Limit (IPv6) from packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: TTL/Hop Limit value or None

#### `get_tcp_flags(packet)`
- **Purpose**: Extracts TCP flags from packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: TCP flags string or None

#### `get_arp_operation(packet)`
- **Purpose**: Extracts ARP operation from packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: Operation code (1 = ARP Request, 2 = ARP Reply) or None

#### `get_dns_query(packet)`
- **Purpose**: Extracts DNS query domain name from packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: Domain name string or None
- **Functionality**: Decodes query if bytes and removes trailing dot

#### `get_dns_query_type(packet)`
- **Purpose**: Extracts DNS query type from packet
- **Parameters**: `packet` - Scapy packet object
- **Returns**: DNS query type (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA) or None
- **Functionality**: Maps DNS type codes to human-readable names

#### `get_dns_answers(packet)`
- **Purpose**: Extracts IPv4/IPv6 addresses from DNS answer records
- **Parameters**: `packet` - Scapy packet object
- **Returns**: List of answer strings (empty list if no answers)
- **Functionality**: Parses DNS answer records and extracts rdata values

#### `extract_features(packet)`
- **Purpose**: Converts a Scapy packet into security-relevant features
- **Parameters**: `packet` - Scapy packet object
- **Returns**: Dictionary containing comprehensive feature set with keys:
  - Basic info: `timestamp`, `packet_length`, `protocol`
  - Ethernet: `src_mac`, `dst_mac`
  - IP: `src_ip`, `dst_ip`, `src_ip_private`, `dst_ip_private`, `ttl`
  - Transport: `src_port`, `dst_port`, `tcp_flags`
  - ARP: `arp_operation`, `arp_src_ip`, `arp_src_mac`, `arp_dst_ip`, `arp_dst_mac`
  - DNS: `dns_query`, `dns_query_type`, `dns_answers`
  - Protocol indicators: `is_dns`, `is_arp`, `is_tcp`, `is_udp`, `is_icmp`
  - Service ports: `is_http`, `is_https`, `is_dns_port`

---

### 5. **database.py** - SQLite Database Module

#### `init_database()`
- **Purpose**: Initializes the SQLite database with required tables
- **Functionality**: Creates `packets` table if it doesn't exist with fields for:
  - Packet timestamps
  - MAC addresses (source and destination)
  - IP addresses (source and destination)
  - Protocol information
  - Port numbers
  - Packet length
  - ARP-specific fields

#### `insert_packet(packet_data)`
- **Purpose**: Inserts a packet record into the database
- **Parameters**: `packet_data` - Dictionary containing packet information
- **Functionality**: Stores parsed packet data in the packets table

#### `get_packet_count()`
- **Purpose**: Retrieves total number of packets stored in database
- **Returns**: Integer count of packets

#### `get_all_packets()`
- **Purpose**: Retrieves all packets from the database
- **Returns**: List of packet records as dictionaries
- **Functionality**: Orders packets by timestamp (most recent first)

#### `get_packets_by_protocol(protocol)`
- **Purpose**: Retrieves packets filtered by protocol type
- **Parameters**: `protocol` - Protocol string (e.g., 'TCP', 'UDP', 'ARP')
- **Returns**: List of matching packet records as dictionaries
- **Functionality**: Orders results by timestamp (most recent first)

---

### 6. **read_packetsdata_db.py** - Database Query Tool

#### `display_packet(packet, index=None)`
- **Purpose**: Displays a packet record in formatted text
- **Parameters**:
  - `packet` - Packet record dictionary from database
  - `index` - Optional packet number for display
- **Functionality**: Prints all packet fields in readable format including ARP fields if present

#### `main()`
- **Purpose**: Main function to demonstrate database query operations
- **Functionality**:
  - Initializes database
  - Gets total packet count
  - Retrieves and displays all packets
  - Filters and displays packets by protocol
  - Provides comprehensive database query examples

---

### 7. **config.py** - Configuration Module

**No methods - contains configuration constants:**
- `INTERFACE` - Network interface identifier (Npcap format)
- `PACKET_LIMIT` - Maximum packets to capture
- `LOG_DIR` - Logging directory path
- `LOG_FILE` - Timestamped log file path

---

### 8. **packet_filter.py** & **packet_logger.py** & **utils.py**
- **Status**: Currently empty (placeholder files for future enhancements)

---

## Workflow Summary

1. **Configuration** → Set network interface and packet limits in `config.py`
2. **Capture** → Run `packet_capture.py` or `packet_capture_l3.py` to start sniffing
3. **Parse** → Captured packets are parsed by `packet_parser.py`
4. **Extract** → Features are extracted using `feature_extractor.py`
5. **Store** → Data is stored in SQLite database via `database.py` methods
6. **Query** → Use `read_packetsdata_db.py` to retrieve and analyze captured packets

---

## Key Dependencies

- **Scapy**: For packet capture and parsing
- **SQLite3**: For database operations
- **Python ipaddress module**: For IP validation