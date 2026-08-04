import re
from utils.url_preprocessing import extract_domain, domain_matches, TRUSTED_DOMAINS

# ---------------- URL SHORTENERS ---------------- #

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly"
]

# ---------------- SUSPICIOUS TLDS ---------------- #

SUSPICIOUS_TLDS = [
    ".xyz",
    ".ru",
    ".tk",
    ".top",
    ".gq",
    ".ml",
    ".cf"
]

# ---------------- URL PHISHING PATTERNS ---------------- #

SUSPICIOUS_PATTERNS = [
    "secure",
    "verify",
    "update",
    "bank",
    "login",
    "signin",
    "wallet",
    "account",
    "payment",
    "billing",
    "support",
    "recovery",
    "reset",
    "confirm",
    "unlock",
    "crypto",
    "bonus"
]

# ---------------- HIGH RISK KEYWORDS ---------------- #

HIGH_RISK_KEYWORDS = [
    "password",
    "passwords",
    "bank",
    "otp",
    "credit card",
    "debit card",
    "cvv",
    "login",
    "signin",
    "verify",
    "account",
    "credentials",
    "authentication",
    "access code"
]

# ---------------- MEDIUM RISK KEYWORDS ---------------- #

MEDIUM_RISK_KEYWORDS = [
    "claim",
    "reward",
    "winner",
    "gift",
    "free",
    "urgent",
    "offer",
    "limited",
    "unlock",
    "benefit",
    "benefits",
    "premium",
    "exclusive",
    "bonus"
]

# ---------------- DANGEROUS PHRASES ---------------- #

DANGEROUS_PHRASES = [
    "enter your password",
    "claim reward",
    "verify your account",
    "bank account",
    "click here",
    "limited offer",
    "urgent action",
    "login immediately",
    "update account",
    "share your password",
    "enter your otp",
    "submit your credentials",
    "provide your cvv"
]

# ---------------- TYPOSQUATTING DOMAINS ---------------- #

TYPO_DOMAINS = [
    "micros0ft",
    "faceb00k",
    "paypa1",
    "g00gle",
    "appl-support"
]

# ---------------- MAIN ENGINE ---------------- #

def analyze_threat(text, urls):

    threat_score = 0
    indicators = []

    text = text.lower()

    trusted_detected = False

    # Trusted domain check — compares the ACTUAL domain of the first
    # detected URL, not a substring match on the raw text. The old
    # substring approach was spoofable: "microsoft.com.evil-verify.tk"
    # contains the literal string "microsoft.com" and would have been
    # wrongly treated as trusted, lowering the threat score for an
    # attacker-controlled domain.

    if urls:
        first_domain = extract_domain(urls[0].lower())

        for domain in TRUSTED_DOMAINS:

            if domain_matches(first_domain, domain):

                trusted_detected = True

                indicators.append(
                    "Trusted domain detected"
                )

    # Keyword detection

    high_matches = 0
    medium_matches = 0

    for keyword in HIGH_RISK_KEYWORDS:

        if keyword in text:

            high_matches += 1

    for keyword in MEDIUM_RISK_KEYWORDS:

        if keyword in text:

            medium_matches += 1

    threat_score += high_matches * 18
    threat_score += medium_matches * 8

    if high_matches > 0:

        indicators.append(
            f"{high_matches} high-risk phishing keywords detected"
        )

    if medium_matches > 0:

        indicators.append(
            f"{medium_matches} suspicious marketing keywords detected"
        )

    # Dangerous phrases

    for phrase in DANGEROUS_PHRASES:

        if phrase in text:

            threat_score += 25

            indicators.append(
                f"Social engineering phrase detected: {phrase}"
            )

    # Credential theft detection

    credential_words = [
        "password",
        "passwords",
        "otp",
        "cvv",
        "pin",
        "credentials",
        "login"
    ]

    action_words = [
        "give",
        "share",
        "provide",
        "enter",
        "submit",
        "send"
    ]

    credential_found = any(
        word in text for word in credential_words
    )

    action_found = any(
        word in text for word in action_words
    )

    if credential_found and action_found:

        threat_score += 35

        indicators.append(
            "Possible credential theft attempt detected"
        )

    # ---------------- URL ANALYSIS ---------------- #

    if urls:

        url = urls[0].lower()
        domain = extract_domain(url)

        # URL shorteners

        if any(
            domain_matches(domain, shortener)
            for shortener in SHORTENERS
        ):

            threat_score += 40

            indicators.append(
                "Shortened URL detected (destination hidden)"
            )
            threat_score = max(threat_score, 40)

        # IP based URLs

        if re.search(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            url
        ):

            threat_score += 25

            indicators.append(
                "IP address used instead of domain"
            )

        # Excessive subdomains

        domain_parts = (
            url.replace("https://", "")
               .replace("http://", "")
               .split("/")[0]
               .split(".")
        )

        if len(domain_parts) > 4:

            threat_score += 20

            indicators.append(
                "Excessive subdomains detected"
            )

        # Suspicious wording

        suspicious_count = 0

        for pattern in SUSPICIOUS_PATTERNS:

            if pattern in url:

                suspicious_count += 1

        if suspicious_count == 1:

            threat_score += 12

            indicators.append(
                "Potentially suspicious domain wording"
            )

        elif suspicious_count == 2:

            threat_score += 25

            indicators.append(
                "Suspicious phishing-style domain detected"
            )

        elif suspicious_count >= 3:

            threat_score += 40

            indicators.append(
                "Highly suspicious phishing domain structure"
            )

        # Suspicious TLD

        for tld in SUSPICIOUS_TLDS:

            if tld in url:

                threat_score += 20

                indicators.append(
                    f"Suspicious TLD detected: {tld}"
                )

        # @ trick

        if "@" in url:

            threat_score += 35

            indicators.append(
                "@ symbol phishing trick detected"
            )

        # Punycode / internationalized domain (homograph attack risk)
        #
        # "xn--" is the ASCII-safe prefix browsers use to encode
        # non-Latin unicode characters in a domain name. It's a
        # legitimate mechanism (real internationalized sites use it),
        # but it's also the exact technique behind homograph attacks —
        # e.g. a Cyrillic "а" that displays identically to Latin "a"
        # in "аpple.com". Not proof of malice on its own, but worth
        # surfacing so a human can look closer.

        if domain.startswith("xn--") or ".xn--" in domain:

            threat_score += 20

            indicators.append(
                "Internationalized domain (punycode) detected — verify this isn't a lookalike character trick"
            )

        # Long URL

        if len(url) > 45:

            threat_score += 10

            indicators.append(
                "Unusually long URL detected"
            )

        # Hyphen detection

        hyphen_count = url.count("-")

        if hyphen_count == 1:

            threat_score += 5

        elif hyphen_count == 2:

            threat_score += 12

            indicators.append(
                "Multiple hyphens detected"
            )

        elif hyphen_count >= 3:

            threat_score += 20

            indicators.append(
                "Excessive hyphen usage detected"
            )

        # Unicode / homograph

        try:

            url.encode("ascii")

        except UnicodeEncodeError:

            threat_score += 40

            indicators.append(
                "Unicode / Homograph attack detected"
            )

        # Typosquatting

        for fake in TYPO_DOMAINS:

            if fake in domain:

                threat_score += 40

                indicators.append(
                    "Typosquatting domain detected"
                )

        # HTTPS check

        if not url.startswith("https://"):

            threat_score += 10

            indicators.append(
                "Non-HTTPS connection detected"
            )

    # Trusted-domain dampening.
    #
    # A domain on the curated TRUSTED_DOMAINS allowlist gets its
    # keyword/wording-heuristic score heavily discounted, rather than
    # trying to surgically exclude individual words. Reason: a bank's
    # own legitimate pages routinely contain words like "banking",
    # "accounts", "signin" as normal business content — no keyword
    # denylist can cleanly separate that from actual phishing wording.
    # Structural red flags (IP-address URLs, typosquatting, excessive
    # subdomains) can't realistically co-occur with a confirmed exact
    # domain match here, so this dampening mainly affects the
    # keyword/wording heuristics, which is exactly what should be
    # discounted for a manually-verified legitimate domain.
    # VirusTotal (checked independently in app.py) can still override
    # this if it finds real evidence.

    if trusted_detected:
        threat_score = threat_score // 4

    # Limits

    threat_score = max(
        0,
        min(threat_score, 100)
    )

    return threat_score, indicators, trusted_detected