from datetime import datetime


class ARPSpoofDetector:
    """
    Detect suspicious changes in IP-to-MAC mappings.

    This module only detects suspicious ARP behavior.
    It does NOT block or isolate the device.
    """

    def __init__(self):
        # Stores known IP -> MAC mappings
        self.ip_mac_table = {}

    def analyze(self, features):
        """
        Analyze extracted packet features.

        Returns:
            Detection event dictionary if suspicious behavior
            is detected, otherwise None.
        """

        # ------------------------------------------------
        # 1. Only analyze ARP packets
        # ------------------------------------------------

        if not features.get("is_arp"):
            return None

        # ------------------------------------------------
        # 2. Get ARP information
        # ------------------------------------------------

        arp_ip = features.get("arp_src_ip")
        arp_mac = features.get("arp_src_mac")
        arp_operation = features.get("arp_operation")

        # ------------------------------------------------
        # 3. Ignore incomplete ARP packets
        # ------------------------------------------------

        if not arp_ip or not arp_mac:
            return None

        # ------------------------------------------------
        # 4. First time seeing this IP
        # ------------------------------------------------

        if arp_ip not in self.ip_mac_table:

            self.ip_mac_table[arp_ip] = arp_mac

            return {
                "timestamp": datetime.now().isoformat(),
                "attack_type": None,
                "source_ip": arp_ip,
                "source_mac": arp_mac,
                "previous_mac": None,
                "arp_operation": arp_operation,
                "severity": "INFO",
                "confidence": 0.0,
                "message": "New IP-MAC mapping observed"
            }

        # ------------------------------------------------
        # 5. Get previously known MAC
        # ------------------------------------------------

        known_mac = self.ip_mac_table[arp_ip]

        # ------------------------------------------------
        # 6. Same IP + same MAC = normal
        # ------------------------------------------------

        if known_mac.lower() == arp_mac.lower():
            return None

        # ------------------------------------------------
        # 7. Same IP + different MAC = suspicious
        # ------------------------------------------------

        return {
            "timestamp": datetime.now().isoformat(),
            "attack_type": "POSSIBLE_ARP_SPOOFING",
            "source_ip": arp_ip,
            "source_mac": arp_mac,
            "previous_mac": known_mac,
            "arp_operation": arp_operation,
            "severity": "HIGH",
            "confidence": 0.85,
            "message": (
                "The same IP address was observed "
                "with a different MAC address"
            )
        }