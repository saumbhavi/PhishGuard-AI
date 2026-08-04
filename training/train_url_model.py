# ==========================================================
# URL PHISHING DETECTION MODEL — TRAINER
# ==========================================================
# Approach: character n-gram TF-IDF + Logistic Regression
#
# Why this approach over hand-picked features (url_length,
# dot_count, etc.)?
#   - Character n-grams automatically learn lexical patterns
#     phishing URLs share (e.g. "paypal-secure-login", IP-like
#     strings, brand name misspellings) without us having to
#     guess and hardcode every suspicious word ourselves.
#   - Works purely from the URL string — no need to fetch the
#     live webpage, so it's fast enough for real-time scanning.
#   - Generalizes better to phishing patterns not seen in
#     training, since it isn't limited to ~7 fixed features.
#
# Dataset: Kaggle "Malicious URLs Dataset" (~651k rows),
# labeled benign / phishing / malware / defacement.
# We collapse malware & defacement into the "malicious" class
# alongside phishing, since the app's job is: is this URL safe
# to click, yes or no.
# ==========================================================

import sys
import os
import pandas as pd
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.url_preprocessing import normalize_url, TRUSTED_DOMAINS as WELL_KNOWN_SAFE_DOMAINS

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

DATA_PATH = "datasets/urls.csv"
MODEL_OUT = "models/url_model.pkl"
VECTORIZER_OUT = "models/url_vectorizer.pkl"
METRICS_OUT = "training/url_model_metrics.txt"

# NOTE: this dataset has a label leak — malware/defacement URLs are
# almost always stored WITH a scheme prefix (http://...), while benign
# URLs are almost always stored WITHOUT one. An un-normalized model
# learns "has http(s)://" as a proxy for "malicious", which fails
# catastrophically in real use (every URL a user pastes from a browser
# has a scheme). normalize_url() removes that shortcut — see
# utils/url_preprocessing.py.

print("=" * 60)
print("  URL PHISHING MODEL TRAINER")
print("=" * 60)

# ---------------- LOAD & CLEAN ---------------- #

df = pd.read_csv(DATA_PATH)
df = df.drop_duplicates(subset="url")
df = df[df["url"].str.len() > 0]

df["label"] = df["type"].map({
    "benign": 0,
    "phishing": 1,
    "malware": 1,
    "defacement": 1,
}).astype(int)

df["url_normalized"] = df["url"].apply(normalize_url)

# ------------------------------------------------------------
# TARGETED DATA AUGMENTATION
#
# Investigation: only ~0.07% of "benign" URLs in this dataset are
# bare domains (no path) — almost all benign examples are full
# content pages like "site.com/article/123". Malicious examples,
# by contrast, are frequently bare domains or brand-name tokens
# (typosquatting/impersonation). Result: the trained model treats
# any short, path-less, well-known domain as out-of-distribution
# and skews toward predicting "malicious" — exactly the input shape
# a real user is most likely to test (pasting "google.com").
#
# Fix: augment the benign class with well-known legitimate domains
# in bare and common-path forms, so the model actually sees what
# normal, safe browsing traffic looks like.
# ------------------------------------------------------------

# WELL_KNOWN_SAFE_DOMAINS is imported from utils/url_preprocessing.py
# (as TRUSTED_DOMAINS) so this list can never drift out of sync with
# the one the rule engine uses at inference time.

COMMON_SAFE_PATHS = [
    "", "/", "/about", "/help", "/contact", "/products", "/blog",
    "/support", "/news", "/careers", "/pricing", "/docs", "/search?q=weather",
]

augmented_rows = []
for domain in WELL_KNOWN_SAFE_DOMAINS:
    for path in COMMON_SAFE_PATHS:
        augmented_rows.append({
            "url_normalized": (domain + path).rstrip("/") if path else domain,
            "label": 0,
        })
    # also a 'www.' + subdomain variant to broaden coverage
    augmented_rows.append({"url_normalized": "www." + domain, "label": 0})

augmented_df = pd.DataFrame(augmented_rows).drop_duplicates(subset="url_normalized")
# Apply the same normalization used elsewhere for consistency
augmented_df["url_normalized"] = augmented_df["url_normalized"].apply(normalize_url)

print(f"\nAugmenting with {len(augmented_df)} well-known-safe-domain examples")

df["sample_weight"] = 1.0
augmented_df["sample_weight"] = 150.0  # up-weighted: a handful of real examples
                                        # would otherwise be drowned out by 636k rows

df = pd.concat(
    [df[["url_normalized", "label", "sample_weight"]], augmented_df],
    ignore_index=True,
).drop_duplicates(subset="url_normalized")

print(f"\nRows after cleaning + augmentation: {len(df)}")
print(df["label"].value_counts())

X = df["url_normalized"]
y = df["label"]
w = df["sample_weight"]

X_train, X_test, y_train, y_test, w_train, w_test = train_test_split(
    X, y, w, test_size=0.20, random_state=42, stratify=y
)

# ---------------- FEATURE EXTRACTION ---------------- #

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=30000,
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print(f"\nLearned {len(vectorizer.get_feature_names_out())} character n-gram features")

# ---------------- TRAIN ---------------- #

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42,
)

model.fit(X_train_vec, y_train, sample_weight=w_train)

# ---------------- EVALUATE ---------------- #

predictions = model.predict(X_test_vec)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
f1 = f1_score(y_test, predictions)
report = classification_report(y_test, predictions)
cm = confusion_matrix(y_test, predictions)

summary = f"""URL PHISHING MODEL — EVALUATION METRICS
Dataset: {DATA_PATH} ({len(df)} rows after cleaning)
Model: TF-IDF (char 3-5 gram, 30k features) + Logistic Regression

Accuracy : {accuracy:.4f}
Precision: {precision:.4f}
Recall   : {recall:.4f}
F1 Score : {f1:.4f}

Confusion Matrix:
{cm}

Classification Report:
{report}
"""

print("\n" + summary)

with open(METRICS_OUT, "w") as f:
    f.write(summary)

# ---------------- SAVE ---------------- #

joblib.dump(model, MODEL_OUT)
joblib.dump(vectorizer, VECTORIZER_OUT)

print(f"Saved model to {MODEL_OUT}")
print(f"Saved vectorizer to {VECTORIZER_OUT}")
print(f"Saved metrics to {METRICS_OUT}")

# ------------------------------------------------------------
# SANITY CHECK — catches dataset-artifact bugs (e.g. the scheme-
# prefix leak this dataset originally had) before shipping a model
# that looks great on paper but fails on everyday real-world input.
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("  SANITY CHECK ON REAL-WORLD-STYLE URLS")
print("=" * 60)

known_safe = [
    "https://www.wikipedia.org",
    "https://www.google.com",
    "https://github.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
]

known_suspicious_patterns = [
    "http://paypal-secure-login-verify-account.tk/signin",
    "http://192.168.1.1/wp-admin/update.php",
    "http://micros0ft-support-verify.xyz/login",
]

sanity_failures = 0

for url in known_safe:
    vec = vectorizer.transform([normalize_url(url)])
    pred = model.predict(vec)[0]
    status = "OK" if pred == 0 else "!! FALSE POSITIVE !!"
    if pred != 0:
        sanity_failures += 1
    print(f"[{status}] expected benign  -> {url}")

for url in known_suspicious_patterns:
    vec = vectorizer.transform([normalize_url(url)])
    pred = model.predict(vec)[0]
    status = "OK" if pred == 1 else "!! FALSE NEGATIVE !!"
    if pred != 1:
        sanity_failures += 1
    print(f"[{status}] expected malicious -> {url}")

if sanity_failures:
    print(f"\n⚠️  {sanity_failures} sanity check(s) failed — inspect the model before deploying.")
else:
    print("\n✓ All sanity checks passed.")
