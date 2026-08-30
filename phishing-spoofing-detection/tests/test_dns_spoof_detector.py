import sys
import os


# =====================================================
# PROJECT PATH
# =====================================================

CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DETECTION_DIR = os.path.dirname(
    CURRENT_DIR
)

sys.path.append(DETECTION_DIR)


from dns_spoof_detector import DNSSpoofDetector


# =====================================================
# CREATE DETECTOR
# =====================================================

detector = DNSSpoofDetector()


# =====================================================
# TEST 1
# FIRST DNS MAPPING
# =====================================================

features_1 = {

    "is_dns": True,

    "dns_query": "example.com",

    "dns_query_type": "A",

    "dns_answers": [
        "93.184.216.34"
    ]
}


result_1 = detector.analyze(
    features_1
)


print("\n========== TEST 1 ==========")

print(result_1)


# =====================================================
# TEST 2
# SAME DNS ANSWER
# =====================================================

features_2 = {

    "is_dns": True,

    "dns_query": "example.com",

    "dns_query_type": "A",

    "dns_answers": [
        "93.184.216.34"
    ]
}


result_2 = detector.analyze(
    features_2
)


print("\n========== TEST 2 ==========")

print(result_2)


# =====================================================
# TEST 3
# DNS ANSWER CHANGED
# =====================================================

features_3 = {

    "is_dns": True,

    "dns_query": "example.com",

    "dns_query_type": "A",

    "dns_answers": [
        "5.6.7.8"
    ]
}


result_3 = detector.analyze(
    features_3
)


print("\n========== TEST 3 ==========")

print(result_3)


# =====================================================
# TEST 4
# PRIVATE DNS ANSWER
# =====================================================

features_4 = {

    "is_dns": True,

    "dns_query": "example.com",

    "dns_query_type": "A",

    "dns_answers": [
        "192.168.1.100"
    ]
}


result_4 = detector.analyze(
    features_4
)


print("\n========== TEST 4 ==========")

print(result_4)


# =====================================================
# DNS HISTORY
# =====================================================

print("\n========== DNS HISTORY ==========")

history = detector.get_dns_history()


for domain, information in history.items():

    print(f"\nDomain: {domain}")

    for key, value in information.items():

        print(
            f"{key:20}: {value}"
        )