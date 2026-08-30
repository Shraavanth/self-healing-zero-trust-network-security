from scapy.all import (
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR
)


# =====================================================
# CREATE DNS RESPONSE PACKET
# =====================================================

dns_packet = (
    Ether(
        src="AA:AA:AA:AA:AA:AA",
        dst="BB:BB:BB:BB:BB:BB"
    )
    /
    IP(
        src="8.8.8.8",
        dst="192.168.1.5"
    )
    /
    UDP(
        sport=53,
        dport=50000
    )
    /
    DNS(
        id=1,
        qr=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A"
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            rdata="93.184.216.34",
            ttl=300
        )
    )
)


# =====================================================
# DISPLAY PACKET
# =====================================================

print("\n========== COMPLETE PACKET ==========\n")

dns_packet.show()


# =====================================================
# DNS LAYER
# =====================================================

dns = dns_packet[DNS]

print("\n========== DNS INFORMATION ==========")

print("ancount :", dns.ancount)
print("an      :", dns.an)


# =====================================================
# CHECK DNS ANSWER
# =====================================================

if dns.an is not None:

    print("\n========== ANSWER FOUND ==========")

    print("Answer type :", type(dns.an))
    print("Record type :", dns.an.type)
    print("Record name :", dns.an.rrname)
    print("Record data :", dns.an.rdata)

else:

    print("\nNO DNS ANSWER FOUND")