from datetime import datetime
from ipaddress import ip_address


class DNSSpoofDetector:
    """
    Stateful DNS anomaly detector.

    This detector looks for suspicious DNS responses
    using the DNS features extracted from Scapy packets.

    It does not automatically declare every unusual
    DNS response as an attack.
    """


    def __init__(self):

        # Stores previously observed DNS answers
        #
        # Example:
        # {
        #     "example.com": {
        #         "answers": {"1.2.3.4"},
        #         "query_count": 3,
        #         "change_count": 0
        #     }
        # }

        self.dns_history = {}


    def _is_private_ip(self, ip):
        """
        Check whether an answer IP is private.
        """

        if not ip:
            return False

        try:
            return ip_address(ip).is_private

        except ValueError:
            return False


    def analyze(self, features):
        """
        Analyze extracted DNS features.

        Returns:
            None for normal DNS traffic.

            Dictionary for suspicious/anomalous DNS traffic.
        """

        # =================================================
        # 1. Make sure this is DNS
        # =================================================

        if not features.get("is_dns"):
            return None


        # =================================================
        # 2. Extract DNS information
        # =================================================

        query = features.get("dns_query")

        query_type = features.get("dns_query_type")

        answers = features.get("dns_answers", [])


        # =================================================
        # 3. Ignore incomplete DNS packets
        # =================================================

        if not query:

            return None


        current_time = datetime.now().isoformat()


        # Make sure answers is always a list

        if answers is None:

            answers = []


        # =================================================
        # 4. Normalize answers
        # =================================================

        normalized_answers = set()

        for answer in answers:

            if isinstance(answer, str):

                normalized_answers.add(
                    answer.strip().lower()
                )


        # =================================================
        # 5. DNS query without an answer
        # =================================================

        if len(normalized_answers) == 0:

            return None


        # =================================================
        # 6. First time seeing this domain
        # =================================================

        if query not in self.dns_history:

            self.dns_history[query] = {

                "answers": normalized_answers,

                "query_count": 1,

                "change_count": 0,

                "first_seen": current_time,

                "last_seen": current_time
            }

            return {
                "timestamp": current_time,

                "attack_type": None,

                "domain": query,

                "query_type": query_type,

                "answers": list(normalized_answers),

                "previous_answers": [],

                "change_count": 0,

                "severity": "INFO",

                "confidence": 0.0,

                "message":
                    "New DNS domain-answer mapping observed"
            }


        # =================================================
        # 7. Existing domain
        # =================================================

        record = self.dns_history[query]

        previous_answers = record["answers"]


        record["query_count"] += 1

        record["last_seen"] = current_time


        # =================================================
        # 8. Same answers = normal
        # =================================================

        if normalized_answers == previous_answers:

            return None


        # =================================================
        # 9. Answer changed
        # =================================================

        record["change_count"] += 1

        change_count = record["change_count"]


        # =================================================
        # 10. Calculate confidence
        # =================================================

        confidence = min(
            0.60 + (change_count * 0.10),
            0.90
        )


        # =================================================
        # 11. Check for private answer
        # =================================================

        private_answer = False

        for answer in normalized_answers:

            if self._is_private_ip(answer):

                private_answer = True

                break


        # =================================================
        # 12. Determine severity
        # =================================================

        if private_answer:

            severity = "HIGH"

        else:

            severity = "MEDIUM"


        # =================================================
        # 13. Update DNS history
        # =================================================

        record["answers"] = normalized_answers


        # =================================================
        # 14. Generate anomaly event
        # =================================================

        return {
            "timestamp": current_time,

            "attack_type":
                "POSSIBLE_DNS_SPOOFING",

            "domain": query,

            "query_type": query_type,

            "answers": list(normalized_answers),

            "previous_answers":
                list(previous_answers),

            "change_count": change_count,

            "severity": severity,

            "confidence": round(
                confidence,
                2
            ),

            "message":
                "DNS answer mapping changed"
        }


    def get_dns_history(self):
        """
        Return current DNS history.
        """

        return self.dns_history