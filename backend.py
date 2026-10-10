from pathlib import Path
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "messages.csv"


def load_model():
    """Train a small local demo model from the included labeled CSV."""
    df = pd.read_csv(DATA_PATH)
    required = {"text", "label"}
    if not required.issubset(df.columns):
        raise ValueError("Dataset must contain 'text' and 'label' columns.")
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df = df[df["label"].isin(["spam", "ham"])]
    if len(df) < 4 or df["label"].nunique() < 2:
        raise ValueError("Dataset needs examples of both spam and ham.")

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        max_features=10000,
    )
    X = vectorizer.fit_transform(df["text"].astype(str))
    model = MultinomialNB(alpha=0.5)
    model.fit(X, df["label"])
    return model, vectorizer, f"{len(df)} labeled demo messages"


def predict_message(text, model, vectorizer):
    X = vectorizer.transform([text])
    probabilities = model.predict_proba(X)[0]
    classes = list(model.classes_)
    spam_index = classes.index("spam")
    ham_index = classes.index("ham")
    label = "spam" if probabilities[spam_index] >= probabilities[ham_index] else "ham"
    confidence = float(probabilities[spam_index] if label == "spam" else probabilities[ham_index])
    return label, confidence


def predict_messages(messages, model, vectorizer):
    """Return prediction results for a list of message texts."""
    cleaned = [str(message).strip() for message in messages if str(message).strip()]
    if not cleaned:
        return []

    transformed = vectorizer.transform(cleaned)
    probabilities = model.predict_proba(transformed)
    classes = list(model.classes_)
    spam_index = classes.index("spam")
    ham_index = classes.index("ham")

    results = []
    for row in probabilities:
        label = "spam" if row[spam_index] >= row[ham_index] else "ham"
        confidence = float(row[spam_index] if label == "spam" else row[ham_index])
        results.append({"label": label, "confidence": confidence})
    return results
