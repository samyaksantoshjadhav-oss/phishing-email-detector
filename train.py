import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ---------------- LOAD DATA ----------------
df = pd.read_csv("data/emails.csv")

# Combine subject and body
df["text"] = df["subject"] + " " + df["body"]

X = df["text"]
y = df["label"]

# ---------------- SPLIT DATA ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ---------------- TF-IDF VECTORIZATION ----------------
vectorizer = TfidfVectorizer()
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# ---------------- MODEL TRAINING ----------------
model = LogisticRegression()
model.fit(X_train_tfidf, y_train)

# ---------------- PREDICTION ----------------
y_pred = model.predict(X_test_tfidf)

# ---------------- EVALUATION ----------------
accuracy = accuracy_score(y_test, y_pred)

print("Model Accuracy:", accuracy)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))

# ---------------- SAVE MODEL ----------------
joblib.dump(model, "models/phishing_model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print("\nModel and Vectorizer saved successfully!")