from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR

from feature_extractor import extract_features


# =====================================================
# TEST 1: TCP PACKET
# =====================================================

tcp_packet = (
    Ether(
        src="AA:BB:CC:DD:EE:FF",
        dst="11:22:33:44:55:66"
    )
    /
    IP(
        src="192.168.1.4",
        dst="8.8.8.8",
        ttl=64
    )
    /
    TCP(
        sport=50000,
        dport=443,
        flags="S"
    )
)

tcp_features = extract_features(tcp_packet)

print("\n========== TCP FEATURES ==========")

for key, value in tcp_features.items():
    print(f"{key:20}: {value}")


# =====================================================
# TEST 2: ARP PACKET
# =====================================================

arp_packet = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    ARP(
        op=2,
        hwsrc="AA:AA:AA:AA:AA:AA",
        psrc="192.168.1.1",
        hwdst="BB:BB:BB:BB:BB:BB",
        pdst="192.168.1.10"
    )
)

arp_features = extract_features(arp_packet)

print("\n========== ARP FEATURES ==========")

for key, value in arp_features.items():
    print(f"{key:20}: {value}")


# =====================================================
# TEST 3: DNS PACKET
# =====================================================

dns_packet = (
    Ether(
        src="AA:BB:CC:DD:EE:FF",
        dst="11:22:33:44:55:66"
    )
    /
    IP(
        src="192.168.1.4",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=50000,
        dport=53
    )
    /
    DNS(
        rd=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A"
        )
    )
)

dns_features = extract_features(dns_packet)

print("\n========== DNS FEATURES ==========")

for key, value in dns_features.items():
    print(f"{key:20}: {value}")