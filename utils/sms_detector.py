"""
SMS / message text phishing-spam detection via a trained ML model.

Model: TF-IDF + Multinomial Naive Bayes, trained on the classic
SMS Spam Collection dataset (see training/train_sms_model.py).
"""

import joblib

MODEL_PATH = "models/sms_model.pkl"
VECTORIZER_PATH = "models/sms_vectorizer.pkl"

_model = joblib.load(MODEL_PATH)
_vectorizer = joblib.load(VECTORIZER_PATH)


def predict_message(text: str):
    """
    Returns (prediction, confidence_percent).
    prediction: 1 = spam/phishing-style message, 0 = legitimate
    confidence_percent: model's probability for the predicted class, 0-100
    """
    vector = _vectorizer.transform([text])
    prediction = int(_model.predict(vector)[0])
    probabilities = _model.predict_proba(vector)[0]
    confidence = probabilities[prediction] * 100
    return prediction, confidence


def explain_message(text: str, top_n: int = 5):
    """
    Returns the words/phrases that contributed most to the model's
    spam/ham decision, as (word, contribution) tuples. Same linear
    feature-attribution approach as utils/ml_detector.explain_url —
    see that function's docstring for why this is mathematically
    equivalent to a SHAP LinearExplainer without the extra dependency.
    """
    vector = _vectorizer.transform([text])
    feature_names = _vectorizer.get_feature_names_out()
    coefficients = _model.coef_[0]

    nonzero_indices = vector.nonzero()[1]

    contributions = [
        (feature_names[i], float(vector[0, i] * coefficients[i]))
        for i in nonzero_indices
    ]

    contributions.sort(key=lambda x: x[1], reverse=True)

    top_spam_signals = [c for c in contributions if c[1] > 0][:top_n]
    top_ham_signals = [c for c in contributions if c[1] < 0][:top_n]

    return {
        "spam_signals": top_spam_signals,
        "ham_signals": top_ham_signals,
    }
