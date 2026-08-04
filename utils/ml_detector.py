"""
URL phishing detection via a trained ML model.

Model: character n-gram (3-5) TF-IDF + Logistic Regression,
trained on ~640k labeled URLs (see training/train_url_model.py).
Test-set performance: 97.2% accuracy, 0.96 F1 (see
training/url_model_metrics.txt for the full report).
"""

import joblib

from utils.url_preprocessing import normalize_url

MODEL_PATH = "models/url_model.pkl"
VECTORIZER_PATH = "models/url_vectorizer.pkl"

_model = joblib.load(MODEL_PATH)
_vectorizer = joblib.load(VECTORIZER_PATH)


def predict_url(url: str):
    """
    Returns (prediction, confidence_percent).
    prediction: 1 = phishing/malicious, 0 = benign
    confidence_percent: model's probability for the predicted class, 0-100
    """
    vector = _vectorizer.transform([normalize_url(url)])
    prediction = int(_model.predict(vector)[0])
    probabilities = _model.predict_proba(vector)[0]
    confidence = probabilities[prediction] * 100
    return prediction, confidence


def explain_url(url: str, top_n: int = 5):
    """
    Returns the character n-grams that contributed most to the model's
    decision, as a list of (ngram, contribution) tuples sorted by
    influence (most positive/phishing-pushing first).

    For a linear model over TF-IDF features, a feature's contribution
    to the decision is exactly (coefficient * TF-IDF value) — this is
    the same quantity a SHAP LinearExplainer would compute, without
    needing the extra `shap` dependency. Only n-grams actually present
    in this URL (nonzero TF-IDF weight) are considered.
    """
    normalized = normalize_url(url)
    vector = _vectorizer.transform([normalized])
    feature_names = _vectorizer.get_feature_names_out()
    coefficients = _model.coef_[0]

    nonzero_indices = vector.nonzero()[1]

    contributions = [
        (feature_names[i], float(vector[0, i] * coefficients[i]))
        for i in nonzero_indices
    ]

    contributions.sort(key=lambda x: x[1], reverse=True)

    top_phishing_signals = [c for c in contributions if c[1] > 0][:top_n]
    top_safe_signals = [c for c in contributions if c[1] < 0][:top_n]

    return {
        "phishing_signals": top_phishing_signals,
        "safe_signals": top_safe_signals,
    }
