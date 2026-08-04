import re

# A curated allowlist of well-known, high-traffic legitimate domains.
# Used in TWO places that must stay in sync:
#   1. utils/threat_engine.py — to avoid flagging these as suspicious
#      and to discount erroneous ML "phishing" predictions against them.
#   2. training/train_url_model.py — as weighted data augmentation, so
#      the ML model actually sees examples of what normal traffic to
#      these domains looks like (see README for why this was needed).
# Single source of truth here prevents the two from drifting apart.

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "netflix.com",
    "yahoo.com", "bing.com", "whatsapp.com", "office.com", "live.com",
    "adobe.com", "salesforce.com", "zoom.us", "dropbox.com", "spotify.com",
    "paypal.com", "ebay.com", "flipkart.com", "wordpress.com", "medium.com",
    "quora.com", "pinterest.com", "tumblr.com", "yelp.com", "imdb.com",
    "cnn.com", "bbc.com", "nytimes.com", "espn.com", "forbes.com",
    "walmart.com", "target.com", "bestbuy.com", "costco.com", "ikea.com",
    "airbnb.com", "booking.com", "uber.com", "lyft.com", "doordash.com",
    "gmail.com", "outlook.com", "protonmail.com", "icloud.com",
    "python.org", "npmjs.com", "docker.com", "kubernetes.io", "mozilla.org",
    "cloudflare.com", "digitalocean.com", "heroku.com", "gitlab.com", "bitbucket.org",
    "coursera.org", "udemy.com", "khanacademy.org", "edx.org", "duolingo.com",
    "irctc.co.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "nseindia.com",
    "gov.uk", "usa.gov", "un.org", "who.int", "nasa.gov", "openai.com",
]


def normalize_url(url: str) -> str:
    """
    Strip scheme (http://, https://) and leading 'www.' so the model
    learns from actual domain/path content rather than superficial
    formatting. Used identically at training time and inference time —
    if these ever drift apart, the model's predictions become
    meaningless (train/serve skew).
    """
    url = str(url).strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    return url


def extract_domain(url: str) -> str:
    """
    Get just the hostname from a URL, e.g.
    'https://www.microsoft.com/en-us' -> 'microsoft.com'

    Two things this specifically has to get right:

    1. URLs with no scheme (e.g. plain 'microsoft.com' typed by a
       user) — added before parsing, since urlparse() silently fails
       to extract a netloc without one (previously caused
       ip_lookup.py to query the WRONG address, falling back to the
       caller's own IP instead of the target domain's).

    2. The classic "@" phishing trick — a URL like
       'http://google.com@evil-tracker.tk/login' visually shows
       "google.com" first, but browsers actually navigate to
       whatever comes AFTER the last '@' (the part before it is
       treated as userinfo/credentials). Using urlparse's raw
       `.netloc` returns the whole "google.com@evil-tracker.tk"
       string, which is neither a real hostname nor the actual
       navigation target — it would break IP lookups and could mask
       the real destination. `.hostname` correctly strips the
       userinfo and returns just 'evil-tracker.tk', matching what a
       browser actually does.
    """
    from urllib.parse import urlparse
    candidate = url if "://" in url else "https://" + url
    domain = (urlparse(candidate).hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def domain_matches(domain: str, target: str) -> bool:
    """
    True if `domain` IS `target` or is a subdomain of it.
    Prevents naive substring bugs like 't.co' matching inside
    'microsoft.com' or 'flipkart.com'.
    """
    return domain == target or domain.endswith("." + target)
