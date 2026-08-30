"""
read_packetsdata_db.py
----------------------
Script to read and query packet data from the SQLite database

This script demonstrates how to use the database module methods
to retrieve and analyze captured packet data.
"""

from database import (
    init_database, 
    insert_packet, 
    get_packet_count,
    get_all_packets,
    get_packets_by_protocol,
    get_packets_by_ip,
    DB_FILE
)


def display_packet(packet, index=None):
    """
    Display a packet record in a formatted way.
    
    Args:
        packet (dict): Packet record from database
        index (int): Optional packet number for display
    """
    prefix = f"Packet {index}:" if index else "Packet:"
    print(f"\n{prefix}")
    print("-" * 60)
    print(f"  Timestamp    : {packet.get('timestamp', 'N/A')}")
    print(f"  Source MAC   : {packet.get('src_mac', 'N/A')}")
    print(f"  Dest MAC     : {packet.get('dst_mac', 'N/A')}")
    print(f"  Source IP    : {packet.get('src_ip', 'N/A')}")
    print(f"  Dest IP      : {packet.get('dst_ip', 'N/A')}")
    print(f"  Protocol     : {packet.get('protocol', 'N/A')}")
    print(f"  Source Port  : {packet.get('src_port', 'N/A')}")
    print(f"  Dest Port    : {packet.get('dst_port', 'N/A')}")
    print(f"  Packet Length: {packet.get('packet_length', 'N/A')} bytes")
    
    # Display ARP-specific fields if present
    if packet.get('arp_src_ip'):
        print(f"  ARP Src IP   : {packet.get('arp_src_ip')}")
        print(f"  ARP Src MAC  : {packet.get('arp_src_mac')}")
        print(f"  ARP Dst IP   : {packet.get('arp_dst_ip')}")
        print(f"  ARP Dst MAC  : {packet.get('arp_dst_mac')}")


def main():
    """
    Main function to demonstrate database query operations.
    """
    print("\n" + "=" * 60)
    print("PACKET DATABASE QUERY TOOL")
    print("=" * 60)
    print(f"Database: {DB_FILE}\n")
    
    try:
        # Initialize database
        print("Initializing database...")
        init_database()
        print("✓ Database initialized\n")
        
        # Get total packet count
        print("-" * 60)
        print("1. TOTAL PACKET COUNT")
        print("-" * 60)
        count = get_packet_count()
        print(f"Total packets in database: {count}\n")
        
        if count == 0:
            print("No packets found in database. Run packet_capture.py first.\n")
            return
        
        # Get all packets
        print("-" * 60)
        print("2. ALL PACKETS")
        print("-" * 60)
        all_packets = get_all_packets()
        print(f"Retrieved {len(all_packets)} packets")
        
        for i, packet in enumerate(all_packets[:5], 1):  # Display first 5
            display_packet(packet, i)
        
        if len(all_packets) > 5:
            print(f"\n... and {len(all_packets) - 5} more packets")
        
        # Query by protocol
        print("\n" + "-" * 60)
        print("3. PACKETS BY PROTOCOL")
        print("-" * 60)
        
        # Get unique protocols
        protocols_set = set()
        for packet in all_packets:
            if packet.get('protocol'):
                protocols_set.add(packet.get('protocol'))
        
        if protocols_set:
            for protocol in sorted(protocols_set):
                protocol_packets = get_packets_by_protocol(protocol)
                print(f"  {protocol}: {len(protocol_packets)} packets")
        else:
            print("  No protocols found")
        
        # Get TCP packets as example
        print("\n  Example - TCP Packets:")
        tcp_packets = get_packets_by_protocol("TCP")
        if tcp_packets:
            for i, packet in enumerate(tcp_packets[:3], 1):
                display_packet(packet, i)
            if len(tcp_packets) > 3:
                print(f"\n  ... and {len(tcp_packets) - 3} more TCP packets")
        else:
            print("  No TCP packets found")
        
        # Query by IP address (if available)
        print("\n" + "-" * 60)
        print("4. PACKETS BY IP ADDRESS")
        print("-" * 60)
        
        # Get a sample IP address from the database
        if all_packets:
            sample_ip = all_packets[0].get('src_ip')
            if sample_ip:
                print(f"  Searching for IP: {sample_ip}")
                ip_packets = get_packets_by_ip(sample_ip)
                print(f"  Found {len(ip_packets)} packet(s) involving {sample_ip}")
                
                for i, packet in enumerate(ip_packets[:3], 1):
                    display_packet(packet, i)
                
                if len(ip_packets) > 3:
                    print(f"\n  ... and {len(ip_packets) - 3} more packets")
            else:
                print("  No IP address available in database")
        
        print("\n" + "=" * 60)
        print("Query Complete!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\nError: {e}\n")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()