"""
detection_event.py
------------------
Defines a unified security detection event.

All detection modules (ARP, DNS, Phishing)
can be converted into the same format.

Author : Shraavanth
"""

from datetime import datetime


class DetectionEvent:

    def __init__(
        self,
        attack_type=None,
        source_ip=None,
        source_mac=None,
        domain=None,
        severity="INFO",
        confidence=0.0,
        risk_score=0,
        message=""
    ):
        self.timestamp = datetime.now().isoformat()

        self.attack_type = attack_type

        self.source_ip = source_ip
        self.source_mac = source_mac

        self.domain = domain

        self.severity = severity
        self.confidence = confidence
        self.risk_score = risk_score

        self.message = message


    def to_dict(self):
        """
        Convert the detection event into a dictionary.
        """

        return {
            "timestamp": self.timestamp,

            "attack_type": self.attack_type,

            "source_ip": self.source_ip,
            "source_mac": self.source_mac,

            "domain": self.domain,

            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,

            "message": self.message
        }


    def __repr__(self):
        """
        Display the detection event clearly.
        """

        return str(self.to_dict())