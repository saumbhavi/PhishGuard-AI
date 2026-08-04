"""
Full-pipeline validation — simulates the exact scoring logic used in
app.py (rule engine + ML model + trusted-domain discount) against a
broad set of real-world-style test cases. Run this before publishing
any changes to make sure the combined system, not just the raw model,
behaves reliably.

Usage: python tests/validate_pipeline.py
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.threat_engine import analyze_threat
from utils.ml_detector import predict_url
from utils.sms_detector import predict_message


def score_url(raw_url: str) -> tuple[int, str]:
    """Mirrors the Threat Scanner logic in app.py."""
    urls = [raw_url]
    threat_score, indicators, trusted_detected = analyze_threat(raw_url, urls)

    prediction, confidence = predict_url(raw_url)

    if prediction == 1:
        if trusted_detected:
            threat_score += 5
        else:
            threat_score += 30

    threat_score = max(0, min(threat_score, 100))
    classification = (
        "Malicious" if threat_score >= 70
        else "Suspicious" if threat_score >= 35
        else "Safe"
    )
    return threat_score, classification


SAFE_URLS = [
    "https://www.google.com",
    "https://google.com",
    "google.com",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com",
    "https://github.com/anthropics",
    "https://www.microsoft.com",
    "https://www.microsoft.com/en-us/microsoft-365",
    "https://www.amazon.com",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://stackoverflow.com/questions/12345",
    "https://www.linkedin.com/in/someone",
    "https://www.youtube.com/watch?v=abc123",
    "https://www.reddit.com/r/programming",
    "https://docs.python.org/3/library/re.html",
    "https://www.nytimes.com/2026/07/25/world/news.html",
    "https://www.paypal.com/signin",
    "https://mail.google.com/mail/u/0/",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.hdfcbank.com/personal/pay/cards/credit-cards",
    "HTTPS://WWW.GOOGLE.COM",
    "https://www.icicibank.com/personal-banking/accounts",
    "https://www.sbi.co.in/web/personal-banking",
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.live.com/login.srf",
    "https://www.apple.com/in/shop/buy-iphone",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://www.cloudflare.com/learning/security/what-is-a-firewall/",
    "https://www.forbes.com/sites/some-author/2026/07/25/some-article/",
    "https://www.espn.com/nfl/scoreboard",
    "https://www.target.com/c/electronics",
    "https://www.walmart.com/browse/electronics",
    "https://www.bestbuy.com/site/laptops",
    "https://www.airbnb.com/rooms/12345678",
    "https://www.booking.com/hotel/us/example.html",
    "https://www.udemy.com/course/python-for-beginners/",
    "https://www.coursera.org/learn/machine-learning",
    "https://gitlab.com/some-user/some-project",
    "https://www.nseindia.com/market-data/live-equity-market",
    "https://who.int/news-room/fact-sheets",
    "https://www.notgoogle.com",  # contains a brand name as substring but no attack pattern — should NOT be flagged just for that
]

MALICIOUS_URLS = [
    "http://paypal-secure-login-verify-account.tk/signin",
    "http://micros0ft-support-verify.xyz/login",
    "http://192.168.1.1/wp-admin/update.php",
    "http://faceb00k-security-alert.ru/confirm",
    "http://appl3-id-locked.top/unlock-account",
    "http://bit.ly/3xK9zP1",
    "http://amazon-account-suspended-verify.ga/signin.php",
    "http://g00gle-drive-shared-document.cf/view",
    "http://secure-bank-update-required.ml/confirm-identity",
    "http://192.168.0.55/admin/reset-password.php",
    "http://netflix-billing-update.gq/payment/confirm",
    "http://hdfcbank.com.verify-kyc-now.tk/login",
    "http://irctc.co.in.ticket-refund-claim.xyz/form",
    "http://sbi-yono-kyc-update.xyz/verify-account",
    "http://linkedin-account-verify-now.ru/login.php",
    "http://update-your-icloud-payment.top/confirm",
    "http://10.0.0.1/login.cgi",
    "http://192.168.1.254/reset.php",
    "http://paypaI.com-secure-verification.info/login",  # capital I instead of l
    "http://www.arnazon.com-order-confirm.xyz/track",  # rn instead of m
    "http://free-gift-card-claim-now.gq/winner",
    "http://your-package-delivery-failed.cf/reschedule",
    "http://covid-relief-fund-claim.ml/apply-now",
    "http://tax-refund-pending-verify.tk/claim",
    "http://whatsapp-verify-account-now.ru/confirm",
    # Edge cases found during manual exploration — see README bug list
    "http://google.com@evil-tracker.tk/login",  # classic @ trick: browser navigates to evil-tracker.tk, not google.com
    "http://notgoogle.com-account-verify-login.tk/signin",  # brand-adjacent name + real attack pattern
    "http://192.168.1.1/notgoogle-login",
    "http://[2001:db8::1]/login",  # IPv6 address
    "http://xn--80ak6aa92e.com",  # punycode / homograph attack risk
]

SAFE_MESSAGES = [
    "Hey, are we still on for lunch tomorrow?",
    "Your Amazon order #123-4567890 has shipped and will arrive Friday.",
    "Reminder: your dentist appointment is at 3pm on Thursday.",
    "Meeting moved to 10am, see you in the conference room.",
    "Thanks for the update, I'll review it tonight.",
    "Can you send me the report before EOD?",
    "Happy birthday! Hope you have a great day.",
    "Your OTP for login is 482913, valid for 10 minutes.",
    "Your package has been delivered to your doorstep.",
    "Don't forget to pick up milk on your way home.",
]

SPAM_MESSAGES = [
    "WINNER!! You have been selected to claim a free prize. Click here now and enter your bank details to claim.",
    "URGENT: Your account will be suspended. Verify your identity immediately at this link or lose access.",
    "Congratulations! You've won a $1000 gift card. Claim now before it expires! Limited time offer!!!",
    "Your bank account has been locked due to suspicious activity. Click here to unlock and confirm your password.",
    "FREE entry in our $5000 prize draw, text WIN to 80086 now, T&Cs apply.",
    "Your Netflix subscription payment failed. Update your card details immediately to avoid losing access.",
    "You have an unclaimed refund of $750 waiting. Click here and enter your bank details to receive it.",
    "SECURITY ALERT: Someone tried to log into your account from a new device. Confirm your password now.",
    "Your Apple ID has been locked for security reasons. Tap here to verify your identity and restore access.",
    "You've been selected for a special cash reward. Reply with your bank account number to claim.",
]


def run():
    print("=" * 70)
    print("  URL PIPELINE VALIDATION")
    print("=" * 70)

    failures = []

    for url in SAFE_URLS:
        score, cls = score_url(url)
        status = "OK " if cls == "Safe" else "FAIL"
        if cls != "Safe":
            failures.append((url, "expected Safe", cls, score))
        print(f"[{status}] {cls:10s} (score={score:3d})  {url}")

    print()

    for url in MALICIOUS_URLS:
        score, cls = score_url(url)
        status = "OK " if cls != "Safe" else "FAIL"
        if cls == "Safe":
            failures.append((url, "expected Suspicious/Malicious", cls, score))
        print(f"[{status}] {cls:10s} (score={score:3d})  {url}")

    print()
    print("=" * 70)
    print("  MESSAGE PIPELINE VALIDATION")
    print("=" * 70)

    for msg in SAFE_MESSAGES:
        pred, conf = predict_message(msg)
        status = "OK " if pred == 0 else "FAIL"
        if pred != 0:
            failures.append((msg, "expected ham", "spam", conf))
        print(f"[{status}] {'spam' if pred else 'ham':6s} ({conf:.0f}%)  {msg[:60]}")

    print()

    for msg in SPAM_MESSAGES:
        pred, conf = predict_message(msg)
        status = "OK " if pred == 1 else "FAIL"
        if pred != 1:
            failures.append((msg, "expected spam", "ham", conf))
        print(f"[{status}] {'spam' if pred else 'ham':6s} ({conf:.0f}%)  {msg[:60]}")

    print()
    print("=" * 70)
    total = len(SAFE_URLS) + len(MALICIOUS_URLS) + len(SAFE_MESSAGES) + len(SPAM_MESSAGES)
    passed = total - len(failures)
    print(f"  RESULT: {passed}/{total} passed ({100*passed/total:.1f}%)")
    print("=" * 70)

    if failures:
        print("\nFailures:")
        for item in failures:
            print(f"  - {item}")

    return len(failures) == 0


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
