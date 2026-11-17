import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .sample_datasets import URL_DATASET, EMAIL_DATASET
from .feature_extractor import extract_url_features, extract_email_features

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)

URL_MODEL_PATH = os.path.join(DATA_DIR, "url_model.joblib")
URL_FEATURE_NAMES_PATH = os.path.join(DATA_DIR, "url_feature_names.joblib")
EMAIL_MODEL_PATH = os.path.join(DATA_DIR, "email_model.joblib")
EMAIL_VEC_PATH = os.path.join(DATA_DIR, "email_vectorizer.joblib")

def train_and_save_models(force_retrain: bool = False):
    """
    Trains the URL Random Forest Classifier and the Email TF-IDF + Classifier models
    if they do not already exist on disk or force_retrain is True.
    """
    url_model_exists = os.path.exists(URL_MODEL_PATH) and os.path.exists(URL_FEATURE_NAMES_PATH)
    email_model_exists = os.path.exists(EMAIL_MODEL_PATH) and os.path.exists(EMAIL_VEC_PATH)

    if url_model_exists and email_model_exists and not force_retrain:
        print("[ML] Pre-trained models found on disk. Ready for inference.")
        return

    print("[ML] Training Machine Learning models for PhishGuard...")

    # 1. Train URL Classifier
    X_url = []
    y_url = []
    feature_keys = None

    for url, label in URL_DATASET:
        feats, _ = extract_url_features(url)
        if feature_keys is None:
            feature_keys = sorted(feats.keys())
        X_url.append([feats[k] for k in feature_keys])
        y_url.append(label)

    X_url = np.array(X_url)
    y_url = np.array(y_url)

    url_clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    url_clf.fit(X_url, y_url)

    joblib.dump(url_clf, URL_MODEL_PATH)
    joblib.dump(feature_keys, URL_FEATURE_NAMES_PATH)
    print(f"[ML] URL RandomForest model trained and saved to {URL_MODEL_PATH}")

    # 2. Train Email Classifier
    corpus = []
    y_email = []

    for subject, sender, body, label in EMAIL_DATASET:
        _, _, combined_text = extract_email_features(body, subject, sender)
        corpus.append(combined_text)
        y_email.append(label)

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1200, stop_words="english")
    X_tfidf = vectorizer.fit_transform(corpus)

    email_clf = LogisticRegression(C=2.0, max_iter=500, random_state=42)
    email_clf.fit(X_tfidf, y_email)

    joblib.dump(email_clf, EMAIL_MODEL_PATH)
    joblib.dump(vectorizer, EMAIL_VEC_PATH)
    print(f"[ML] Email NLP model trained and saved to {EMAIL_MODEL_PATH}")

if __name__ == "__main__":
    train_and_save_models(force_retrain=True)

