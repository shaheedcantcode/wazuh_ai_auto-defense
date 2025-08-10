#!/usr/bin/env python3
import os, json, pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from typing import Dict

CONFIG_FILE = "/home/sbd/wazuh_ai_config.json"
default_config = {
    "DATASET_FILE": "/home/sbd/wazuh_ai_training_data.csv",
    "HUMAN_REVIEW_FILE": "/home/sbd/human_review.csv",
    "MODEL_FILE": "/home/sbd/wazuh_ai_model.pkl",
    "VECTORIZER_FILE": "/home/sbd/wazuh_ai_vectorizer.pkl"
}
config: Dict[str, str] = json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else default_config

def validate_config(cfg: Dict[str, str]) -> None:
    for key in ["DATASET_FILE", "HUMAN_REVIEW_FILE", "MODEL_FILE", "VECTORIZER_FILE"]:
        dir_path = os.path.dirname(cfg[key])
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)
validate_config(config)

if not os.path.exists(config["HUMAN_REVIEW_FILE"]):
    print("No human_review.csv found — nothing to retrain.")
    exit()

review_df = pd.read_csv(config["HUMAN_REVIEW_FILE"])
if review_df.empty:
    print("No entries to review.")
    exit()

print("Reviewing entries:\n")
for idx, row in review_df.iterrows():
    print(f"{idx}: [{row['confidence']:.2f}%] {row['description']} (Predicted: {row['predicted_severity']})")
    correct_label = input("Enter correct severity (Low/Medium/High/Critical) or press Enter to keep: ").strip()
    if correct_label:
        review_df.at[idx, 'predicted_severity'] = correct_label

if os.path.exists(config["DATASET_FILE"]):
    train_df = pd.read_csv(config["DATASET_FILE"])
else:
    train_df = pd.DataFrame(columns=["description", "severity"])

append_df = review_df.rename(columns={"predicted_severity": "severity"})
train_df = pd.concat([train_df, append_df[["description", "severity"]]], ignore_index=True)
train_df.to_csv(config["DATASET_FILE"], index=False)

print("Retraining model...")
vectorizer = TfidfVectorizer()
X_train = vectorizer.fit_transform(train_df["description"])
y_train = train_df["severity"]
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

joblib.dump(model, config["MODEL_FILE"])
joblib.dump(vectorizer, config["VECTORIZER_FILE"])
os.remove(config["HUMAN_REVIEW_FILE"])

print("Retraining complete. Model updated and human_review.csv cleared.")
