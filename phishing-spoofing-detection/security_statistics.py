"""
security_statistics.py
----------------------
Security Monitoring Statistics

Tracks packets and security detection events.

Author : Shraavanth
"""


class SecurityStatistics:

    def __init__(self):

        # =============================================
        # PACKET COUNTERS
        # =============================================

        self.total_packets = 0

        # =============================================
        # EVENT COUNTERS
        # =============================================

        self.total_events = 0

        self.arp_spoofing_events = 0

        self.dns_spoofing_events = 0

        self.phishing_events = 0

        # =============================================
        # SEVERITY COUNTERS
        # =============================================

        self.high_events = 0

        self.medium_events = 0

        self.info_events = 0


    # =================================================
    # RECORD PACKET
    # =================================================

    def record_packet(self):
        """
        Increment total packet count.
        """

        self.total_packets += 1


    # =================================================
    # RECORD SECURITY EVENT
    # =================================================

    def record_event(self, event):
        """
        Record a DetectionEvent.
        """

        if event is None:
            return

        # ---------------------------------------------
        # Convert event to dictionary
        # ---------------------------------------------

        if hasattr(event, "to_dict"):

            data = event.to_dict()

        elif isinstance(event, dict):

            data = event

        else:

            return

        # ---------------------------------------------
        # Total events
        # ---------------------------------------------

        self.total_events += 1

        # ---------------------------------------------
        # Attack type
        # ---------------------------------------------

        attack_type = data.get(
            "attack_type"
        )

        if attack_type == "POSSIBLE_ARP_SPOOFING":

            self.arp_spoofing_events += 1

        elif attack_type == "POSSIBLE_DNS_SPOOFING":

            self.dns_spoofing_events += 1

        elif attack_type == "POSSIBLE_PHISHING":

            self.phishing_events += 1

        # ---------------------------------------------
        # Severity
        # ---------------------------------------------

        severity = data.get(
            "severity"
        )

        if severity == "HIGH":

            self.high_events += 1

        elif severity == "MEDIUM":

            self.medium_events += 1

        elif severity == "INFO":

            self.info_events += 1


    # =================================================
    # GET STATISTICS
    # =================================================

    def get_statistics(self):
        """
        Return all statistics as a dictionary.
        """

        return {

            "total_packets":
                self.total_packets,

            "total_events":
                self.total_events,

            "arp_spoofing_events":
                self.arp_spoofing_events,

            "dns_spoofing_events":
                self.dns_spoofing_events,

            "phishing_events":
                self.phishing_events,

            "high_events":
                self.high_events,

            "medium_events":
                self.medium_events,

            "info_events":
                self.info_events
        }


    # =================================================
    # DISPLAY SUMMARY
    # =================================================

    def display_summary(self):
        """
        Print security monitoring summary.
        """

        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("SECURITY MONITORING SUMMARY")
        print("=" * 60)

        print(
            f"Packets Processed       : "
            f"{stats['total_packets']}"
        )

        print(
            f"Security Events         : "
            f"{stats['total_events']}"
        )

        print("\nAttack Type Statistics")
        print("-" * 60)

        print(
            f"ARP Spoofing            : "
            f"{stats['arp_spoofing_events']}"
        )

        print(
            f"DNS Spoofing            : "
            f"{stats['dns_spoofing_events']}"
        )

        print(
            f"Phishing                : "
            f"{stats['phishing_events']}"
        )

        print("\nSeverity Statistics")
        print("-" * 60)

        print(
            f"HIGH                    : "
            f"{stats['high_events']}"
        )

        print(
            f"MEDIUM                  : "
            f"{stats['medium_events']}"
        )

        print(
            f"INFO                    : "
            f"{stats['info_events']}"
        )

        print("=" * 60)