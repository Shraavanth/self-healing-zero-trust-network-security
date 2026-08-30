from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether


def get_protocol(packet):
    """
    Identify the main protocol present in the packet.
    """

    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IP):
        return "IP"

    if packet.haslayer(IPv6):
        return "IPv6"

    return "UNKNOWN"


def parse_packet(packet):
    """
    Extract useful information from a Scapy packet.
    """

    data = {
        "src_mac": None,
        "dst_mac": None,

        "src_ip": None,
        "dst_ip": None,

        "protocol": get_protocol(packet),

        "src_port": None,
        "dst_port": None,

        "packet_length": len(packet),

        # ARP-specific fields
        "arp_src_ip": None,
        "arp_src_mac": None,
        "arp_dst_ip": None,
        "arp_dst_mac": None
    }

    # ---------------------------------
    # Ethernet information
    # ---------------------------------

    if packet.haslayer(Ether):
        data["src_mac"] = packet[Ether].src
        data["dst_mac"] = packet[Ether].dst

    # ---------------------------------
    # IPv4 information
    # ---------------------------------

    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst

    # ---------------------------------
    # IPv6 information
    # ---------------------------------

    elif packet.haslayer(IPv6):
        data["src_ip"] = packet[IPv6].src
        data["dst_ip"] = packet[IPv6].dst

    # ---------------------------------
    # ARP information
    # ---------------------------------

    if packet.haslayer(ARP):
        data["arp_src_ip"] = packet[ARP].psrc
        data["arp_src_mac"] = packet[ARP].hwsrc

        data["arp_dst_ip"] = packet[ARP].pdst
        data["arp_dst_mac"] = packet[ARP].hwdst

    # ---------------------------------
    # TCP information
    # ---------------------------------

    if packet.haslayer(TCP):
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport

    # ---------------------------------
    # UDP information
    # ---------------------------------

    elif packet.haslayer(UDP):
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    return data