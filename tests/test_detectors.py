"""
Basic sanity tests for the detection modules.
Run with: pytest tests/
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.ml_detector import predict_url
from utils.sms_detector import predict_message
from utils.threat_engine import analyze_threat


def test_predict_url_returns_valid_shape():
    prediction, confidence = predict_url("https://www.google.com")
    assert prediction in (0, 1)
    assert 0 <= confidence <= 100


def test_predict_url_flags_obvious_phishing_pattern():
    prediction, confidence = predict_url(
        "http://paypal-secure-login-verify-account.tk/signin"
    )
    assert prediction == 1


def test_predict_url_allows_known_safe_domain():
    prediction, confidence = predict_url("https://www.wikipedia.org")
    assert prediction == 0


def test_predict_message_returns_valid_shape():
    prediction, confidence = predict_message("Hey, are we still on for lunch?")
    assert prediction in (0, 1)
    assert 0 <= confidence <= 100


def test_predict_message_flags_spam_pattern():
    prediction, confidence = predict_message(
        "WINNER!! You have been selected to claim a free prize. "
        "Click here now and enter your bank details to claim."
    )
    assert prediction == 1


def test_threat_engine_flags_ip_based_url():
    score, indicators, _trusted = analyze_threat(
        "click here", ["http://192.168.1.1/login"]
    )
    assert score > 0
    assert any("IP address" in i for i in indicators)


def test_threat_engine_low_score_for_benign_text():
    score, indicators, _trusted = analyze_threat("Let's meet at 5pm tomorrow.", [])
    assert score < 35


def test_threat_engine_trusted_domain_not_flagged_as_shortener():
    # Regression test: naive substring matching used to flag any domain
    # ending in "t.com" (microsoft.com, flipkart.com, target.com...) as
    # the "t.co" URL shortener, and trusted-domain lookup used to match
    # on substrings of the raw text rather than the actual domain.
    for domain in ["https://www.microsoft.com", "https://www.flipkart.com"]:
        score, indicators, _trusted = analyze_threat(domain, [domain])
        assert not any("shortener" in i.lower() for i in indicators)
        assert any("trusted domain" in i.lower() for i in indicators)


def test_threat_engine_rejects_spoofed_lookalike_domain():
    # Regression test: "microsoft.com.evil.tk" contains the literal
    # substring "microsoft.com" and used to be wrongly treated as a
    # trusted domain, lowering its threat score.
    spoofed = "http://microsoft.com.verify-account-security.tk/login"
    score, indicators, _trusted = analyze_threat(spoofed, [spoofed])
    assert not any("trusted domain" in i.lower() for i in indicators)
    assert score >= 35
