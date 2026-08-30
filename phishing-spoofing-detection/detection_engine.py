"""
detection_engine.py
-------------------
Unified Security Detection Engine.

Connects:
1. ARP Spoofing Detection
2. DNS Spoofing Detection
3. Phishing Detection

Converts all detection results into a
common DetectionEvent format.

Author : Shraavanth
"""

from arp_spoof_detector import ARPSpoofDetector
from dns_spoof_detector import DNSSpoofDetector
from phishing_detector import PhishingDetector
from detection_event import DetectionEvent


class DetectionEngine:

    def __init__(self):

        # =============================================
        # CREATE DETECTORS
        # =============================================

        self.arp_detector = ARPSpoofDetector()

        self.dns_detector = DNSSpoofDetector()

        self.phishing_detector = PhishingDetector()


    # =================================================
    # CONVERT RESULT TO UNIFIED EVENT
    # =================================================

    def create_event(self, result):

        """
        Convert a detector result into a
        unified DetectionEvent.
        """

        if result is None:
            return None


        # =============================================
        # ARP RESULT
        # =============================================

        if result.get("attack_type") == "POSSIBLE_ARP_SPOOFING":

            return DetectionEvent(

                attack_type=result.get(
                    "attack_type"
                ),

                source_ip=result.get(
                    "source_ip"
                ),

                source_mac=result.get(
                    "source_mac"
                ),

                severity=result.get(
                    "severity",
                    "INFO"
                ),

                confidence=result.get(
                    "confidence",
                    0.0
                ),

                risk_score=int(
                    result.get(
                        "confidence",
                        0.0
                    ) * 100
                ),

                message=result.get(
                    "message",
                    ""
                )
            )


        # =============================================
        # DNS RESULT
        # =============================================

        if result.get("attack_type") == "POSSIBLE_DNS_SPOOFING":

            return DetectionEvent(

                attack_type=result.get(
                    "attack_type"
                ),

                domain=result.get(
                    "domain"
                ),

                severity=result.get(
                    "severity",
                    "INFO"
                ),

                confidence=result.get(
                    "confidence",
                    0.0
                ),

                risk_score=int(
                    result.get(
                        "confidence",
                        0.0
                    ) * 100
                ),

                message=result.get(
                    "message",
                    ""
                )
            )


        # =============================================
        # PHISHING RESULT
        # =============================================

        if result.get("attack_type") == "POSSIBLE_PHISHING":

            return DetectionEvent(

                attack_type=result.get(
                    "attack_type"
                ),

                domain=result.get(
                    "domain"
                ),

                severity=result.get(
                    "severity",
                    "INFO"
                ),

                confidence=result.get(
                    "confidence",
                    0.0
                ),

                risk_score=result.get(
                    "risk_score",
                    0
                ),

                message=result.get(
                    "message",
                    ""
                )
            )


        # =============================================
        # INFORMATIONAL RESULT
        # =============================================

        return DetectionEvent(

            attack_type=result.get(
                "attack_type"
            ),

            source_ip=result.get(
                "source_ip"
            ),

            source_mac=result.get(
                "source_mac"
            ),

            domain=result.get(
                "domain"
            ),

            severity=result.get(
                "severity",
                "INFO"
            ),

            confidence=result.get(
                "confidence",
                0.0
            ),

            risk_score=result.get(
                "risk_score",
                0
            ),

            message=result.get(
                "message",
                ""
            )
        )


    # =================================================
    # ANALYZE PACKET
    # =================================================

    def analyze_packet(self, features):

        """
        Send packet features to the
        appropriate detection module.
        """

        # =============================================
        # ARP SPOOFING
        # =============================================

        if features.get("is_arp"):

            result = self.arp_detector.analyze(
                features
            )

            if result is not None:

                return self.create_event(
                    result
                )


        # =============================================
        # DNS SPOOFING
        # =============================================

        if features.get("is_dns"):

            result = self.dns_detector.analyze(
                features
            )

            if result is not None:

                return self.create_event(
                    result
                )


        # =============================================
        # PHISHING DETECTION
        # =============================================

        domain = features.get(
            "dns_query"
        )

        if domain:

            result = self.phishing_detector.analyze(
                domain
            )

            if result is not None:

                return self.create_event(
                    result
                )


        # =============================================
        # NO THREAT
        # =============================================

        return None