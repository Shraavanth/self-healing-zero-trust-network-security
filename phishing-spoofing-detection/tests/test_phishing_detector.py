"""
test_phishing_detector.py
-------------------------
Tests for the PhishingDetector.

Author : Shraavanth
"""

import os
import sys


# =====================================================
# PROJECT PATH SETUP
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DETECTION_DIR = os.path.dirname(
    CURRENT_DIR
)

if DETECTION_DIR not in sys.path:
    sys.path.append(DETECTION_DIR)


# =====================================================
# IMPORT PHISHING DETECTOR
# =====================================================

from phishing_detector import PhishingDetector


# =====================================================
# CREATE DETECTOR
# =====================================================

detector = PhishingDetector()


# =====================================================
# TEST 1 - NORMAL DOMAIN
# =====================================================

print(
    "\n========== TEST 1 : NORMAL DOMAIN =========="
)

domain = "google.com"

result = detector.analyze(
    domain
)

print(
    "Domain :",
    domain
)

print(
    "Result :",
    result
)


# =====================================================
# TEST 2 - SUSPICIOUS DOMAIN
# =====================================================

print(
    "\n========== TEST 2 : SUSPICIOUS DOMAIN =========="
)

domain = "secure-paypal-login.com"

result = detector.analyze(
    domain
)

print(
    "Domain :",
    domain
)

print(
    "Result :",
    result
)


# =====================================================
# TEST 3 - IP ADDRESS
# =====================================================

print(
    "\n========== TEST 3 : IP ADDRESS =========="
)

domain = "192.168.1.100"

result = detector.analyze(
    domain
)

print(
    "Domain :",
    domain
)

print(
    "Result :",
    result
)


# =====================================================
# TEST 4 - MULTIPLE DOMAIN INDICATORS
# =====================================================

print(
    "\n========== TEST 4 : MULTIPLE INDICATORS =========="
)

domain = (
    "secure.account.verify-login.com"
)

result = detector.analyze(
    domain
)

print(
    "Domain :",
    domain
)

print(
    "Result :",
    result
)


# =====================================================
# TEST 5 - URL PATH FEATURE EXTRACTION
# =====================================================

print(
    "\n========== TEST 5 : URL PATH =========="
)

url = (
    "https://example.com/"
    "account/verify-password?id=123"
)

result = detector.extract_domain_features(
    url
)

print(
    "URL :",
    url
)

print(
    "Domain        :",
    result["domain"]
)

print(
    "Path          :",
    result["path"]
)

print(
    "Path Length   :",
    result["path_length"]
)

print(
    "Path Depth    :",
    result["path_depth"]
)

print(
    "Query Present :",
    result["query_present"]
)

print(
    "Path Keywords :",
    result["suspicious_path_keywords"]
)

print(
    "Path Keyword Count :",
    result[
        "suspicious_path_keyword_count"
    ]
)


# =====================================================
# TEST 6 - FULL URL PHISHING ANALYSIS
# =====================================================

print(
    "\n========== TEST 6 : FULL URL ANALYSIS =========="
)

url = (
    "https://example.com/"
    "account/verify-password?id=123"
)

result = detector.analyze(
    url
)

print(
    "URL :",
    url
)

print(
    "Result :",
    result
)


# =====================================================
# TEST 7 - NORMAL URL
# =====================================================

print(
    "\n========== TEST 7 : NORMAL URL =========="
)

url = (
    "https://example.com/"
    "products/shoes"
)

result = detector.analyze(
    url
)

print(
    "URL :",
    url
)

print(
    "Result :",
    result
)
# =====================================================
# TEST 8 - URL ENCODING
# =====================================================

print(
    "\n========== TEST 8 : URL ENCODING =========="
)

url = (
    "https://example.com/"
    "%6c%6f%67%69%6e"
)

features = detector.extract_domain_features(
    url
)

print(
    "URL :",
    url
)

print(
    "Domain              :",
    features["domain"]
)

print(
    "Path                :",
    features["path"]
)

print(
    "Contains URL Encoding:",
    features["contains_url_encoding"]
)

print(
    "Path Keywords       :",
    features["suspicious_path_keywords"]
)

print(
    "Risk Score           :",
    detector.calculate_risk_score(
        features
    )
)
# =====================================================
# TEST 9 - SUSPICIOUS QUERY PARAMETERS
# =====================================================

print(
    "\n========== TEST 9 : QUERY PARAMETERS =========="
)

url = (
    "https://example.com/login"
    "?password=123"
    "&token=abc"
    "&redirect=home"
)

features = detector.extract_domain_features(
    url
)

print(
    "URL :",
    url
)

print(
    "Domain :",
    features["domain"]
)

print(
    "Path :",
    features["path"]
)

print(
    "Query Present :",
    features["query_present"]
)

print(
    "Query Parameters :",
    features["query_parameters"]
)

print(
    "Suspicious Query Keywords :",
    features[
        "suspicious_query_keywords"
    ]
)

print(
    "Suspicious Query Keyword Count :",
    features[
        "suspicious_query_keyword_count"
    ]
)

print(
    "Risk Score :",
    detector.calculate_risk_score(
        features
    )
)
# =====================================================
# TEST 10 - FULL QUERY PHISHING ANALYSIS
# =====================================================

print(
    "\n========== TEST 10 : FULL QUERY ANALYSIS =========="
)

url = (
    "https://example.com/login"
    "?password=123"
    "&token=abc"
    "&redirect=home"
)

result = detector.analyze(
    url
)

print(
    "URL :",
    url
)

print(
    "Detection Result :",
    result
)