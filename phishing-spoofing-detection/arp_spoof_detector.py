from datetime import datetime


class ARPSpoofDetector:
    """
    Stateful ARP spoofing detector.

    Maintains IP-to-MAC mappings and detects
    suspicious changes in those mappings.
    """

    def __init__(self):

        # ------------------------------------------------
        # IP -> ARP information
        # ------------------------------------------------

        self.ip_mac_table = {}


    def analyze(self, features):
        """
        Analyze extracted ARP features.

        Returns a detection event dictionary.
        Returns None for normal repeated traffic.
        """

        # =================================================
        # 1. Check whether packet is ARP
        # =================================================

        if not features.get("is_arp"):
            return None


        # =================================================
        # 2. Extract ARP information
        # =================================================

        arp_ip = features.get("arp_src_ip")
        arp_mac = features.get("arp_src_mac")
        arp_operation = features.get("arp_operation")


        # =================================================
        # 3. Validate information
        # =================================================

        if not arp_ip or not arp_mac:
            return None


        arp_mac = arp_mac.lower()


        # =================================================
        # 4. Current timestamp
        # =================================================

        current_time = datetime.now().isoformat()


        # =================================================
        # 5. First time seeing this IP
        # =================================================

        if arp_ip not in self.ip_mac_table:

            self.ip_mac_table[arp_ip] = {
                "mac": arp_mac,
                "first_seen": current_time,
                "last_seen": current_time,
                "change_count": 0,
                "last_operation": arp_operation
            }

            return {
                "timestamp": current_time,
                "attack_type": None,
                "source_ip": arp_ip,
                "source_mac": arp_mac,
                "previous_mac": None,
                "arp_operation": arp_operation,
                "change_count": 0,
                "severity": "INFO",
                "confidence": 0.0,
                "message": "New IP-MAC mapping observed"
            }


        # =================================================
        # 6. Existing IP
        # =================================================

        existing_record = self.ip_mac_table[arp_ip]

        known_mac = existing_record["mac"]


        # Update last seen information

        existing_record["last_seen"] = current_time
        existing_record["last_operation"] = arp_operation


        # =================================================
        # 7. Same IP + Same MAC
        # =================================================

        if known_mac == arp_mac:

            return None


        # =================================================
        # 8. IP-MAC CHANGE DETECTED
        # =================================================

        existing_record["change_count"] += 1


        change_count = existing_record["change_count"]


        # =================================================
        # 9. Calculate confidence
        # =================================================

        confidence = min(
            0.70 + (change_count * 0.05),
            0.95
        )


        # =================================================
        # 10. Update mapping
        # =================================================

        previous_mac = known_mac

        existing_record["mac"] = arp_mac


        # =================================================
        # 11. Generate detection event
        # =================================================

        return {
            "timestamp": current_time,
            "attack_type": "POSSIBLE_ARP_SPOOFING",
            "source_ip": arp_ip,
            "source_mac": arp_mac,
            "previous_mac": previous_mac,
            "arp_operation": arp_operation,
            "change_count": change_count,
            "severity": "HIGH",
            "confidence": round(confidence, 2),
            "message": (
                "IP-MAC mapping changed "
                "from "
                f"{previous_mac} "
                "to "
                f"{arp_mac}"
            )
        }


    def get_ip_mac_table(self):
        """
        Return the current IP-MAC mapping table.
        """

        return self.ip_mac_table