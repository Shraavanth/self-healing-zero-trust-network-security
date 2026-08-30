"""
phishing_detector.py
--------------------
Module 2 - Phishing Detection

Analyzes domains and URLs and extracts
phishing-related characteristics.

Author : Shraavanth
"""

import re
from urllib.parse import urlparse, parse_qs


class PhishingDetector:

    def __init__(self):

        # =================================================
        # SUSPICIOUS DOMAIN / PATH KEYWORDS
        # =================================================

        self.suspicious_keywords = {
            "login",
            "signin",
            "sign-in",
            "verify",
            "verification",
            "secure",
            "security",
            "account",
            "update",
            "confirm",
            "confirmation",
            "password",
            "bank",
            "banking",
            "wallet",
            "payment",
            "billing",
            "credential",
            "recover",
            "unlock"
        }

        # =================================================
        # SUSPICIOUS QUERY PARAMETERS
        # =================================================

        self.suspicious_query_keywords = {
            "password",
            "passwd",
            "pwd",
            "token",
            "auth",
            "authentication",
            "session",
            "sessionid",
            "credential",
            "login",
            "signin",
            "verify",
            "verification",
            "account",
            "redirect",
            "return",
            "next",
            "confirm"
        }


    # =====================================================
    # DOMAIN / URL FEATURE EXTRACTION
    # =====================================================

    def extract_domain_features(self, domain):

        if not domain:
            return None

        original_domain = domain.strip()

        url_for_parsing = original_domain

        # -------------------------------------------------
        # Add scheme if missing
        # -------------------------------------------------

        if not url_for_parsing.startswith(
            ("http://", "https://")
        ):

            url_for_parsing = (
                "http://" + url_for_parsing
            )


        # -------------------------------------------------
        # Parse URL
        # -------------------------------------------------

        parsed_url = urlparse(
            url_for_parsing
        )

        domain = parsed_url.hostname

        if not domain:
            return None

        domain = domain.lower()


        # =================================================
        # PATH
        # =================================================

        url_path = parsed_url.path

        path_length = len(url_path)

        path_parts = [
            part
            for part in url_path.split("/")
            if part
        ]

        path_depth = len(path_parts)


        # =================================================
        # QUERY
        # =================================================

        url_query = parsed_url.query

        query_present = bool(
            url_query
        )


        # -------------------------------------------------
        # Parse query parameters
        # -------------------------------------------------

        query_parameters_dict = parse_qs(
            url_query,
            keep_blank_values=True
        )

        query_parameters = list(
            query_parameters_dict.keys()
        )

        query_parameters = [
            parameter.lower()
            for parameter in query_parameters
        ]

        query_parameters.sort()


        # =================================================
        # SUSPICIOUS QUERY PARAMETERS
        # =================================================

        suspicious_query_keywords = []

        for parameter in query_parameters:

            if parameter in (
                self.suspicious_query_keywords
            ):

                suspicious_query_keywords.append(
                    parameter
                )


        suspicious_query_keywords = list(
            set(suspicious_query_keywords)
        )

        suspicious_query_keywords.sort()

        suspicious_query_keyword_count = len(
            suspicious_query_keywords
        )


        # =================================================
        # URL ENCODING
        # =================================================

        contains_url_encoding = bool(
            re.search(
                r"%[0-9a-fA-F]{2}",
                original_domain
            )
        )


        # =================================================
        # PATH KEYWORDS
        # =================================================

        path_lower = url_path.lower()

        suspicious_path_keywords = []

        for keyword in self.suspicious_keywords:

            if keyword in path_lower:

                suspicious_path_keywords.append(
                    keyword
                )


        suspicious_path_keywords.sort()

        suspicious_path_keyword_count = len(
            suspicious_path_keywords
        )


        # =================================================
        # DOMAIN FEATURES
        # =================================================

        domain_length = len(domain)

        dot_count = domain.count(".")

        hyphen_count = domain.count("-")

        digit_count = sum(
            character.isdigit()
            for character in domain
        )


        # =================================================
        # SUBDOMAIN COUNT
        # =================================================

        parts = domain.split(".")

        if len(parts) >= 3:

            subdomain_count = len(parts) - 2

        else:

            subdomain_count = 0


        # =================================================
        # DOMAIN KEYWORDS
        # =================================================

        found_keywords = []

        for keyword in self.suspicious_keywords:

            if keyword in domain:

                found_keywords.append(
                    keyword
                )


        found_keywords.sort()

        suspicious_keyword_count = len(
            found_keywords
        )


        # =================================================
        # IP ADDRESS
        # =================================================

        ip_pattern = (
            r"^(?:\d{1,3}\.){3}"
            r"\d{1,3}$"
        )

        contains_ip = bool(
            re.match(
                ip_pattern,
                domain
            )
        )


        # =================================================
        # @ SYMBOL
        # =================================================

        contains_at_symbol = (
            "@" in original_domain
        )


        # =================================================
        # EXCESSIVE DOTS
        # =================================================

        excessive_dots = (
            dot_count >= 4
        )


        # =================================================
        # EXCESSIVE HYPHENS
        # =================================================

        excessive_hyphens = (
            hyphen_count >= 3
        )


        # =================================================
        # RETURN FEATURES
        # =================================================

        return {

            "domain":
                domain,

            "domain_length":
                domain_length,

            "dot_count":
                dot_count,

            "hyphen_count":
                hyphen_count,

            "digit_count":
                digit_count,

            "subdomain_count":
                subdomain_count,

            "path":
                url_path,

            "path_length":
                path_length,

            "path_depth":
                path_depth,

            "query_present":
                query_present,

            "query_parameters":
                query_parameters,

            "suspicious_query_keywords":
                suspicious_query_keywords,

            "suspicious_query_keyword_count":
                suspicious_query_keyword_count,

            "contains_url_encoding":
                contains_url_encoding,

            "suspicious_keywords":
                found_keywords,

            "suspicious_keyword_count":
                suspicious_keyword_count,

            "suspicious_path_keywords":
                suspicious_path_keywords,

            "suspicious_path_keyword_count":
                suspicious_path_keyword_count,

            "contains_ip":
                contains_ip,

            "contains_at_symbol":
                contains_at_symbol,

            "excessive_dots":
                excessive_dots,

            "excessive_hyphens":
                excessive_hyphens
        }


    # =====================================================
    # RISK SCORE
    # =====================================================

    def calculate_risk_score(self, features):

        if not features:
            return 0

        score = 0


        # =================================================
        # DOMAIN KEYWORDS
        # =================================================

        score += (
            features["suspicious_keyword_count"]
            * 15
        )


        # =================================================
        # PATH KEYWORDS
        # =================================================

        score += (
            features[
                "suspicious_path_keyword_count"
            ]
            * 10
        )


        # =================================================
        # QUERY KEYWORDS
        # =================================================

        score += (
            features[
                "suspicious_query_keyword_count"
            ]
            * 10
        )


        # =================================================
        # IP ADDRESS
        # =================================================

        if features["contains_ip"]:

            score += 45


        # =================================================
        # HYPHENS
        # =================================================

        score += (
            features["hyphen_count"]
            * 5
        )


        # =================================================
        # DIGITS
        # =================================================

        score += (
            features["digit_count"]
            * 2
        )


        # =================================================
        # SUBDOMAINS
        #
        # Multiple subdomains alone are NOT considered
        # suspicious.
        #
        # Only add a small score when there are both
        # many subdomains and suspicious keywords.
        # =================================================

        if (
            features["subdomain_count"] >= 3
            and
            features["suspicious_keyword_count"] > 0
        ):

            score += 5


        # =================================================
        # @ SYMBOL
        # =================================================

        if features["contains_at_symbol"]:

            score += 25


        # =================================================
        # URL ENCODING
        # =================================================

        if features["contains_url_encoding"]:

            score += 15


        # =================================================
        # EXCESSIVE DOTS
        # =================================================

        if features["excessive_dots"]:

            score += 15


        # =================================================
        # EXCESSIVE HYPHENS
        # =================================================

        if features["excessive_hyphens"]:

            score += 15


        # =================================================
        # LONG DOMAIN
        # =================================================

        if features["domain_length"] > 30:

            score += 10


        # =================================================
        # LONG PATH
        # =================================================

        if features["path_length"] > 40:

            score += 10


        # =================================================
        # DEEP PATH
        # =================================================

        if features["path_depth"] >= 4:

            score += 10


        # =================================================
        # QUERY PRESENT
        # =================================================

        if features["query_present"]:

            score += 5


        # =================================================
        # LIMIT SCORE
        # =================================================

        score = min(
            score,
            100
        )

        return score


    # =====================================================
    # RISK CLASSIFICATION
    # =====================================================

    def classify_risk(self, score):

        if score >= 60:

            return "HIGH"

        elif score >= 30:

            return "MEDIUM"

        else:

            return "LOW"


    # =====================================================
    # PHISHING ANALYSIS
    # =====================================================

    def analyze(self, domain):

        features = self.extract_domain_features(
            domain
        )

        if features is None:
            return None


        # -------------------------------------------------
        # Calculate risk
        # -------------------------------------------------

        score = self.calculate_risk_score(
            features
        )


        # -------------------------------------------------
        # Classify risk
        # -------------------------------------------------

        severity = self.classify_risk(
            score
        )


        # -------------------------------------------------
        # Confidence
        # -------------------------------------------------

        confidence = round(
            score / 100,
            2
        )


        # -------------------------------------------------
        # LOW RISK
        # -------------------------------------------------

        if severity == "LOW":

            return None


        # =================================================
        # DETECTION MESSAGE
        # =================================================

        # -------------------------------------------------
        # Query parameters
        # -------------------------------------------------

        if features[
            "suspicious_query_keywords"
        ]:

            keyword_text = ", ".join(
                features[
                    "suspicious_query_keywords"
                ]
            )

            message = (
                "Suspicious URL query "
                "parameters detected. "
                f"Keywords: {keyword_text}"
            )


        # -------------------------------------------------
        # URL encoding
        # -------------------------------------------------

        elif features[
            "contains_url_encoding"
        ]:

            message = (
                "URL contains encoded "
                "characters that may indicate "
                "obfuscation"
            )


        # -------------------------------------------------
        # Suspicious path
        # -------------------------------------------------

        elif features[
            "suspicious_path_keywords"
        ]:

            keyword_text = ", ".join(
                features[
                    "suspicious_path_keywords"
                ]
            )

            message = (
                "Suspicious URL path "
                "characteristics detected. "
                f"Keywords: {keyword_text}"
            )


        # -------------------------------------------------
        # Suspicious domain keywords
        # -------------------------------------------------

        elif features[
            "suspicious_keywords"
        ]:

            keyword_text = ", ".join(
                features[
                    "suspicious_keywords"
                ]
            )

            message = (
                "Suspicious domain "
                "characteristics detected. "
                f"Keywords: {keyword_text}"
            )


        # -------------------------------------------------
        # IP address
        # -------------------------------------------------

        elif features[
            "contains_ip"
        ]:

            message = (
                "Domain uses an IP address "
                "instead of a conventional "
                "domain name"
            )


        # -------------------------------------------------
        # @ symbol
        # -------------------------------------------------

        elif features[
            "contains_at_symbol"
        ]:

            message = (
                "URL contains an @ symbol"
            )


        # -------------------------------------------------
        # Other suspicious characteristics
        # -------------------------------------------------

        else:

            message = (
                "Multiple suspicious URL "
                "characteristics detected"
            )


        # =================================================
        # RETURN RESULT
        # =================================================

        return {

            "attack_type":
                "POSSIBLE_PHISHING",

            "domain":
                features["domain"],

            "severity":
                severity,

            "confidence":
                confidence,

            "risk_score":
                score,

            "suspicious_keywords":
                features[
                    "suspicious_keywords"
                ],

            "suspicious_path_keywords":
                features[
                    "suspicious_path_keywords"
                ],

            "suspicious_query_keywords":
                features[
                    "suspicious_query_keywords"
                ],

            "contains_url_encoding":
                features[
                    "contains_url_encoding"
                ],

            "message":
                message
        }


# =====================================================
# DIRECT TEST
# =====================================================

if __name__ == "__main__":

    detector = PhishingDetector()

    test_domains = [

        "google.com",

        "secure-paypal-login.com",

        "192.168.1.100",

        "secure.account.verify-login.com",

        "mobile.events.data.microsoft.com"
    ]


    print("\n" + "=" * 60)
    print("PHISHING DETECTOR TEST")
    print("=" * 60)


    for domain in test_domains:

        print("\n" + "=" * 60)
        print(
            f"Testing Domain : {domain}"
        )
        print("=" * 60)


        result = detector.analyze(
            domain
        )


        if result is None:

            print(
                "Detection Result : NONE"
            )

        else:

            print(
                f"Attack Type       : "
                f"{result['attack_type']}"
            )

            print(
                f"Domain            : "
                f"{result['domain']}"
            )

            print(
                f"Severity          : "
                f"{result['severity']}"
            )

            print(
                f"Confidence        : "
                f"{result['confidence']}"
            )

            print(
                f"Risk Score        : "
                f"{result['risk_score']}"
            )

            print(
                f"Keywords          : "
                f"{result['suspicious_keywords']}"
            )

            print(
                f"Path Keywords     : "
                f"{result['suspicious_path_keywords']}"
            )

            print(
                f"Query Keywords    : "
                f"{result['suspicious_query_keywords']}"
            )

            print(
                f"URL Encoding      : "
                f"{result['contains_url_encoding']}"
            )

            print(
                f"Message           : "
                f"{result['message']}"
            )