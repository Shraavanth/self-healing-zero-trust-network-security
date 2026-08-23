from scapy.all import IP, TCP, ARP, Ether

from packet_parser import parse_packet


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
        dst="8.8.8.8"
    )
    /
    TCP(
        sport=50000,
        dport=443
    )
)

tcp_result = parse_packet(tcp_packet)

print("\n========== PARSED TCP PACKET ==========")

for key, value in tcp_result.items():
    print(f"{key:15}: {value}")


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

arp_result = parse_packet(arp_packet)

print("\n========== PARSED ARP PACKET ==========")

for key, value in arp_result.items():
    print(f"{key:15}: {value}")