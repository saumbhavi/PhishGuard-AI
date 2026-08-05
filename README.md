# 🛡️ AI-Powered Phishing & Threat Intelligence System

A Streamlit-based security tool that scans URLs and messages for phishing
indicators, combining a trained ML model, a rule-based threat-scoring
engine, and live threat intelligence (VirusTotal + IP geolocation).

🔗 **Live demo:** https://phishguard-ai-cijlfrkpgrfqfefx5qjasr.streamlit.app/

## What it does

- **URL Threat Scanner** — paste a URL, get an ML-based verdict, a rule-based
  threat score (0-100), a list of specific red flags found, IP/geo info, a
  live VirusTotal cross-check, and an expandable "why did the AI decide
  this" breakdown showing the exact patterns that drove the verdict.
- **Message Scanner** — paste SMS/email text and get a phishing/spam
  classification independent of URL analysis, with the same explainability
  breakdown.
- **Dashboard** — live stats, risk level, and a trend chart over your scan
  history.
- **Threat Intelligence view** — aggregate stats and detection-capability
  overview.
- **Logs** — full scan history.

## Architecture

```
User input
   │
   ├─► Rule-based threat engine (utils/threat_engine.py)
   │     keyword/phrase matching, shortener & IP-URL detection,
   │     typosquatting patterns, trusted-domain allowlist
   │
   ├─► ML model (utils/ml_detector.py)
   │     character n-gram TF-IDF + Logistic Regression
   │     trained on ~640k labeled URLs
   │
   ├─► SMS/message model (utils/sms_detector.py)
   │     TF-IDF + Naive Bayes, trained on SMS Spam Collection
   │
   └─► VirusTotal API + IP geolocation (live lookups)
         │
         ▼
   Combined threat score → Safe / Suspicious / Malicious
```

The rule engine and ML model are deliberately kept as separate signals that
get combined, rather than one replacing the other — this is a
defense-in-depth design: each layer catches things the other one misses (see
"Bugs found & fixed" below for a concrete example of why this mattered).

## Explainability

Both the URL and message scanners include a "Why did the AI decide this?"
expander showing the exact features that drove the model's verdict.

For a linear model over TF-IDF features (what both models here are), a
feature's contribution to the decision is exactly
`coefficient × TF-IDF weight` — this is the same quantity a SHAP
`LinearExplainer` would compute, so this gives genuine, mathematically
correct feature attribution without adding the extra `shap` dependency.
See `explain_url()` in `utils/ml_detector.py` and `explain_message()` in
`utils/sms_detector.py`.

## Model performance

**URL model** (TF-IDF char n-grams + Logistic Regression, trained on ~640k
URLs from a Kaggle malicious-URL dataset, augmented with weighted
well-known-domain examples):

| Metric | Score |
|---|---|
| Accuracy | 91.9% |
| Precision | 0.84 |
| Recall | 0.93 |
| F1 | 0.88 |

**SMS/message model** (TF-IDF word n-grams + Logistic Regression, SMS Spam
Collection dataset, augmented with phishing-style and legitimate
transactional message examples):

| Metric | Score |
|---|---|
| Accuracy | 97.3% |
| Precision | 0.94 |
| Recall | 0.84 |
| F1 | 0.89 |

Full reports in `training/url_model_metrics.txt` and
`training/sms_model_metrics.txt`.

**Full-pipeline validation:** `tests/validate_pipeline.py` runs the *combined*
system (rule engine + ML model + trust logic, exactly as it runs in the live
app) against 92 realistic test cases — well-known safe sites, phishing
URLs, typosquats, lookalike domains, IP-based URLs, banking pages, safe
and spam messages, edge cases (uppercase URLs, no-scheme URLs, deep paths).
**Current result: 92/92 (100%).** Run it yourself with:
```bash
python tests/validate_pipeline.py
```
This is more meaningful than the raw model metrics above — the raw URL
model alone still misclassifies a couple of well-known bare domains (see
below), but the combined pipeline corrects for that.

**On honesty of these numbers:** the URL model's raw accuracy dropped from
an initial 97% to 92% after fixing a dataset bug (below) — that's the
correct number for a model that actually generalizes to real input, not a
worse model. A high score from a model quietly exploiting a dataset
artifact is worse than a modest score from one that isn't.

## Bugs found & fixed

Digging into this project surfaced eight real, non-obvious bugs — documenting
them here because *finding and fixing bugs like these is a bigger signal of
skill than a clean accuracy number.*

1. **Dataset label leak (scheme prefix).** In the training data, malicious
   URLs were almost always stored with `http://`/`https://`, while benign
   ones almost never were. The model learned "has a scheme" as a proxy for
   "malicious." Fixed by normalizing URLs (strip scheme/`www.`) identically
   at training and inference time (`utils/url_preprocessing.py`).

2. **Under-represented benign shape.** Even after the fix above, well-known
   bare domains (`google.com`, `github.com`) were still occasionally
   misclassified, because <0.1% of "benign" training examples were bare
   domains. Fixed via targeted, weighted data augmentation with well-known
   safe domains, plus an automated sanity check that runs after every
   training pass. Two edge cases (`github.com`, `microsoft.com`) still trip
   the raw ML model even after this — they're caught by the trusted-domain
   logic below instead (defense in depth).

3. **URL-shortener false positive via substring matching.** The rule engine
   checked `"t.co" in url`, which matches inside `microsoft.com`,
   `flipkart.com`, `target.com`. Fixed by parsing the actual hostname and
   comparing it properly (`extract_domain` / `domain_matches` in
   `utils/url_preprocessing.py`).

4. **Trusted-domain spoofing vulnerability.** Same root cause, worse
   consequence: the trusted-domain allowlist checked
   `"microsoft.com" in text`, so `microsoft.com.verify-account.tk` would be
   wrongly treated as trusted and have its threat score *lowered*. Fixed
   the same way — compare the parsed domain, not a substring of raw text.

5. **Flat ML penalty overpowering trusted-domain checks.** The app added a
   flat `+30` to the threat score any time the ML model said "phishing,"
   even against a confirmed trusted domain — meaning bug #2's known ML
   false positives could push a legitimate site into "Suspicious"/
   "Malicious." Fixed by discounting the ML penalty when the domain is on
   the trusted allowlist.

6. **Keyword heuristics false-positiving on legitimate business content.**
   A bank's own real pages (e.g. `icicibank.com/personal-banking/accounts`)
   naturally contain words like "banking," "accounts," "signin" — the same
   vocabulary the phishing-keyword heuristics look for. No keyword denylist
   can cleanly separate that from real phishing wording, so trusted domains
   now get their rule-engine score heavily dampened instead, with
   VirusTotal (checked independently) able to override if it finds real
   evidence.

7. **IP lookup silently querying the wrong address.** `ip_lookup.py` used
   `urlparse(url).netloc` without checking for a scheme prefix — a URL
   typed without `http://`/`https://` in front made `netloc` come back
   empty, causing `ip-api.com` to silently fall back to looking up the
   *caller's own* IP instead of the target site's. Fixed by reusing the
   same tested `extract_domain()` helper everywhere.

8. **Dashboard crash on fresh install.** The default tab read
   `logs/scan_history.csv` with no error handling — before a single scan had
   run, the file didn't exist and the app crashed on first load. Fixed with
   a fallback empty DataFrame.

9. **The classic "@" URL trick broke domain extraction.** A URL like
   `http://google.com@evil-tracker.tk/login` visually shows `google.com`
   first, but browsers actually navigate to whatever comes *after* the
   last `@` — the part before it is treated as userinfo/credentials.
   `extract_domain()` was using `urlparse().netloc`, which returns the
   *entire* raw string including the userinfo
   (`"google.com@evil-tracker.tk"`) — not a real hostname, and not what a
   browser actually navigates to. This silently broke IP lookups and could
   have masked the true destination. Fixed by switching to
   `urlparse().hostname`, which correctly strips the userinfo per the URL
   spec. Found via manual edge-case testing, not the original automated
   suite — a good reminder that adversarial-style manual testing catches
   things systematic test generation doesn't think to try.

10. **No explicit detection for punycode/homograph domains.** Domains using
    `xn--` encoding (the mechanism behind visually-deceptive unicode
    lookalike characters, e.g. a Cyrillic "а" that displays identically to
    Latin "a") weren't flagged as worth a second look. Added an explicit
    rule for this in `utils/threat_engine.py`.

All of these are covered by regression tests in `tests/test_detectors.py`
and the broader `tests/validate_pipeline.py` (92 test cases, 100% passing).

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # then add your own VirusTotal API key
streamlit run app.py
```

Get a free VirusTotal API key at https://www.virustotal.com/gui/join-us.
The app works without one (VirusTotal checks are simply skipped), but the
key it originally shipped with is dead — **if you're the original author,
revoke it in the VirusTotal dashboard**, it should never have been
committed to source.

## Retraining the models

Datasets aren't included in this repo (they're large). To retrain:

```bash
# URL model — needs datasets/urls.csv (Kaggle "Malicious URLs dataset")
python training/train_url_model.py

# SMS model — needs datasets/spam.csv (SMS Spam Collection, tab-separated)
python training/train_sms_model.py
```

Both scripts print full metrics and (for the URL model) run an automated
sanity check against known-safe and known-malicious URLs before you ship a
retrained model.

## Testing

```bash
# Unit tests for individual functions
pip install pytest
pytest tests/

# Full-pipeline validation (rule engine + ML + trust logic combined,
# against 92 realistic real-world cases, including adversarial edge cases like the classic "@" URL trick) — run this after any change
# to threat_engine.py, ml_detector.py, or the trained models
python tests/validate_pipeline.py
```

## Known limitations / next steps

- The rule engine's keyword lists are hand-curated and English-only.
- The trusted-domain allowlist (`TRUSTED_DOMAINS` in
  `utils/url_preprocessing.py`) is manually curated and finite — an
  unlisted-but-legitimate site gets no special treatment, which is the
  correct/safe default, but means the list is worth extending if you
  find real sites getting flagged.
- SMS model recall on spam is 84% — some phishing-style texts may still
  slip through as "ham." A larger training set or a transformer-based
  model would likely push this further; the current model is a linear
  classifier trained on ~5,200 examples.
- No live webpage fetching (page title, favicon, form fields) — the
  PhiUSIIL-style richer feature set would need that and is a good stretch
  goal for anyone extending this.
- No authentication/rate limiting on the Streamlit app itself if deployed
  publicly.

## Tech stack

Python, scikit-learn, Streamlit, Plotly, pandas, VirusTotal API,
ip-api.com.
