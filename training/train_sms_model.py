# ==========================================================
# SMS / MESSAGE PHISHING-SPAM MODEL — TRAINER
# ==========================================================
# Approach: TF-IDF (word 1-2 grams) + Logistic Regression
# Dataset: SMS Spam Collection (ham/spam labeled messages),
# augmented with curated phishing-style urgency examples —
# see PHISHING_STYLE_SPAM below for why.
# ==========================================================

import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)

DATA_PATH = "datasets/spam.csv"
MODEL_OUT = "models/sms_model.pkl"
VECTORIZER_OUT = "models/sms_vectorizer.pkl"
METRICS_OUT = "training/sms_model_metrics.txt"

print("=" * 60)
print("  SMS / MESSAGE PHISHING-SPAM MODEL TRAINER")
print("=" * 60)

df = pd.read_csv(
    DATA_PATH,
    sep="\t",
    names=["label", "message"],
    encoding="latin-1",
)

df["label"] = df["label"].map({"ham": 0, "spam": 1})

# ------------------------------------------------------------
# TARGETED AUGMENTATION
#
# The SMS Spam Collection dataset is mostly commercial/premium-rate
# spam ("free ringtones", "win a prize, text WIN to..."). It's
# under-representative of account-phishing-style urgency messages
# ("your account will be suspended, verify now") — exactly the
# pattern this project is meant to catch. Augmenting with weighted
# phishing-style examples fixes that blind spot, same technique used
# for the URL model (see training/train_url_model.py).
# ------------------------------------------------------------

PHISHING_STYLE_SPAM = [
    "URGENT: Your account will be suspended. Verify your identity immediately at this link or lose access.",
    "Your bank account has been locked due to suspicious activity. Click here to unlock and confirm your password.",
    "Your account has been compromised. Verify your identity now to avoid permanent suspension.",
    "Security alert: unusual sign-in detected. Confirm your password immediately to secure your account.",
    "Your payment could not be processed. Update your billing details now to avoid service interruption.",
    "Action required: your subscription will be cancelled unless you verify your account within 24 hours.",
    "We detected unauthorized access to your account. Click here to reset your password now.",
    "Your card has been temporarily blocked. Verify your CVV and details to reactivate.",
    "Final notice: your account will be permanently deleted unless you confirm your details today.",
    "Your parcel delivery failed. Update your payment information to reschedule delivery.",
    "Unusual login attempt detected from a new device. Verify it was you or your account will be locked.",
    "Your tax refund is pending. Confirm your bank details to receive payment.",
    "Your Netflix payment failed. Update your card details now to avoid losing access.",
    "IMPORTANT: verify your account now, failure to do so will result in permanent suspension.",
    "Your OTP has expired. Click here to generate a new one and confirm your identity.",
    "We noticed suspicious activity on your account. Confirm your credentials to restore access.",
    "Your Apple ID has been locked for security reasons. Verify now to regain access.",
    "Congratulations, you have been selected for a cash reward. Confirm your bank account to claim.",
]

df["sample_weight"] = 1.0

augmented_msgs = pd.DataFrame({
    "label": [1] * len(PHISHING_STYLE_SPAM),
    "message": PHISHING_STYLE_SPAM,
    "sample_weight": 8.0,
})

# Legitimate transactional messages — modern messaging is full of real
# OTPs, delivery notices, and account activity alerts that share
# surface vocabulary with phishing (numbers, "account", "verify",
# "delivered") but are completely benign. Without examples like these,
# the model over-fires on ordinary day-to-day texts.
LEGITIMATE_TRANSACTIONAL = [
    "Your OTP for login is 482913, valid for 10 minutes. Do not share this with anyone.",
    "Your package has been delivered to your doorstep.",
    "Your package has been delivered. Thank you for shopping with us.",
    "Your parcel was delivered today at 2:15pm.",
    "Your order has been shipped and will arrive within 3-5 business days.",
    "Your order has been delivered successfully.",
    "Your verification code is 559204.",
    "Your table reservation for 7pm tonight is confirmed.",
    "Your monthly account statement is now available to view online.",
    "Payment of $42.50 to Electric Co. was successful.",
    "Your ride is arriving in 3 minutes.",
    "Your flight AI202 is on time, departing at 6:45pm from Gate 12.",
    "Your appointment has been confirmed for Monday at 10am.",
    "Thanks for your payment, your account balance is now $0.",
    "Your subscription renewal was successful, thank you for being a member.",
]

augmented_ham = pd.DataFrame({
    "label": [0] * len(LEGITIMATE_TRANSACTIONAL),
    "message": LEGITIMATE_TRANSACTIONAL,
    "sample_weight": 12.0,
})

df = pd.concat([df, augmented_msgs, augmented_ham], ignore_index=True).drop_duplicates(subset="message")

X = df["message"]
y = df["label"]
w = df["sample_weight"]

vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
X_vectorized = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test, w_train, w_test = train_test_split(
    X_vectorized, y, w, test_size=0.2, random_state=42, stratify=y
)

model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
model.fit(X_train, y_train, sample_weight=w_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
f1 = f1_score(y_test, predictions)
report = classification_report(y_test, predictions)

summary = f"""SMS / MESSAGE SPAM-PHISHING MODEL — EVALUATION METRICS
Dataset: {DATA_PATH} ({len(df)} rows, incl. {len(PHISHING_STYLE_SPAM)} augmented phishing-style examples)
Model: TF-IDF (word 1-2 gram) + Logistic Regression (class_weight=balanced)

Accuracy : {accuracy:.4f}
Precision: {precision:.4f}
Recall   : {recall:.4f}
F1 Score : {f1:.4f}

Classification Report:
{report}
"""

print("\n" + summary)

with open(METRICS_OUT, "w") as f:
    f.write(summary)

joblib.dump(model, MODEL_OUT)
joblib.dump(vectorizer, VECTORIZER_OUT)

print(f"Saved model to {MODEL_OUT}")
print(f"Saved vectorizer to {VECTORIZER_OUT}")
