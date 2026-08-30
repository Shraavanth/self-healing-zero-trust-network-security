from datetime import datetime
from ipaddress import ip_address

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR
)

from packet_parser import parse_packet


# =====================================================
# IP FEATURE
# =====================================================

def is_private_ip(ip):
    """
    Check whether an IP address belongs to a private network.
    """

    if not ip:
        return None

    try:
        return ip_address(ip).is_private

    except ValueError:
        return None


# =====================================================
# TTL FEATURE
# =====================================================

def get_ttl(packet):
    """
    Extract TTL from IPv4 or Hop Limit from IPv6.
    """

    if packet.haslayer(IP):
        return packet[IP].ttl

    if packet.haslayer(IPv6):
        return packet[IPv6].hlim

    return None


# =====================================================
# TCP FEATURE
# =====================================================

def get_tcp_flags(packet):
    """
    Extract TCP flags.
    """

    if packet.haslayer(TCP):
        return str(packet[TCP].flags)

    return None


# =====================================================
# ARP FEATURE
# =====================================================

def get_arp_operation(packet):
    """
    Extract ARP operation.

    1 = ARP Request
    2 = ARP Reply
    """

    if packet.haslayer(ARP):
        return packet[ARP].op

    return None


# =====================================================
# DNS QUERY FEATURE
# =====================================================

def get_dns_query(packet):
    """
    Extract DNS query domain.
    """

    if packet.haslayer(DNSQR):

        query = packet[DNSQR].qname

        if isinstance(query, bytes):
            query = query.decode(errors="ignore")

        return query.rstrip(".")

    return None


# =====================================================
# DNS QUERY TYPE FEATURE
# =====================================================

def get_dns_query_type(packet):
    """
    Extract DNS query type.
    """

    if packet.haslayer(DNSQR):

        query_type = packet[DNSQR].qtype

        dns_types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA"
        }

        return dns_types.get(
            query_type,
            str(query_type)
        )

    return None


# =====================================================
# DNS ANSWER FEATURE
# =====================================================

def get_dns_answers(packet):
    """
    Extract IPv4/IPv6 addresses from DNS answers.

    Returns an empty list when the packet is a DNS query
    or when there are no DNS answer records.
    """

    answers = []

    # Packet does not contain DNS
    if not packet.haslayer(DNS):
        return answers

    dns = packet[DNS]

    # DNS query has no answer records
    if dns.ancount is None or dns.ancount == 0:
        return answers

    try:

        for i in range(int(dns.ancount)):

            answer = dns.an[i]

            if hasattr(answer, "rdata"):

                rdata = answer.rdata

                if isinstance(rdata, bytes):
                    rdata = rdata.decode(
                        errors="ignore"
                    )

                answers.append(str(rdata))

    except Exception:
        pass

    return answers


# =====================================================
# MAIN FEATURE EXTRACTION FUNCTION
# =====================================================

def extract_features(packet):
    """
    Convert a Scapy packet into security-relevant features.
    """

    # ---------------------------------------------
    # Use existing packet parser
    # ---------------------------------------------

    parsed = parse_packet(packet)

    # ---------------------------------------------
    # Create feature dictionary
    # ---------------------------------------------

    features = {

        # -----------------------------------------
        # Timestamp
        # -----------------------------------------

        "timestamp": datetime.now().isoformat(),

        # -----------------------------------------
        # Basic packet information
        # -----------------------------------------

        "packet_length": parsed["packet_length"],
        "protocol": parsed["protocol"],

        # -----------------------------------------
        # Ethernet
        # -----------------------------------------

        "src_mac": parsed["src_mac"],
        "dst_mac": parsed["dst_mac"],

        # -----------------------------------------
        # IP
        # -----------------------------------------

        "src_ip": parsed["src_ip"],
        "dst_ip": parsed["dst_ip"],

        # -----------------------------------------
        # IP derived features
        # -----------------------------------------

        "src_ip_private": is_private_ip(
            parsed["src_ip"]
        ),

        "dst_ip_private": is_private_ip(
            parsed["dst_ip"]
        ),

        "ttl": get_ttl(packet),

        # -----------------------------------------
        # Transport layer
        # -----------------------------------------

        "src_port": parsed["src_port"],
        "dst_port": parsed["dst_port"],

        "tcp_flags": get_tcp_flags(packet),

        # -----------------------------------------
        # ARP
        # -----------------------------------------

        "arp_operation": get_arp_operation(packet),

        "arp_src_ip": parsed["arp_src_ip"],
        "arp_src_mac": parsed["arp_src_mac"],

        "arp_dst_ip": parsed["arp_dst_ip"],
        "arp_dst_mac": parsed["arp_dst_mac"],

        # -----------------------------------------
        # DNS
        # -----------------------------------------

        "dns_query": get_dns_query(packet),

        "dns_query_type": get_dns_query_type(packet),

        "dns_answers": get_dns_answers(packet)
    }

    # =================================================
    # PROTOCOL INDICATORS
    # =================================================

    features["is_dns"] = bool(
        packet.haslayer(DNS)
    )

    features["is_arp"] = bool(
        packet.haslayer(ARP)
    )

    features["is_tcp"] = bool(
        packet.haslayer(TCP)
    )

    features["is_udp"] = bool(
        packet.haslayer(UDP)
    )

    features["is_icmp"] = bool(
        packet.haslayer(ICMP)
    )

    # =================================================
    # COMMON SERVICE PORTS
    # =================================================

    features["is_http"] = (
        features["src_port"] == 80
        or
        features["dst_port"] == 80
    )

    features["is_https"] = (
        features["src_port"] == 443
        or
        features["dst_port"] == 443
    )

    features["is_dns_port"] = (
        features["src_port"] == 53
        or
        features["dst_port"] == 53
    )

    # =================================================
    # RETURN FEATURES
    # =================================================

    return features