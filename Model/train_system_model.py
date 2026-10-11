import os
import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE = os.path.join(BASE_DIR, "Processing", "system_ml_features.jsonl")
MODEL_OUTPUT = os.path.join(BASE_DIR, "Model", "system_anomaly_model.pkl")

def train_model():
    print("[*] Loading system feature data...")
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Error: Training data not found at {INPUT_FILE}")
        return

    # Load JSONL data into a Pandas DataFrame
    data = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data.append(json.loads(line.strip()))
            except:
                continue

    df = pd.DataFrame(data)
    
    if len(df) < 10:
        print("[!] Not enough data. Let your pipeline run longer to collect more baseline data.")
        return

    # Define the core features to train on
    ml_features = [
        "avg_cpu_percent", 
        "max_memory_percent", 
        "max_network_connections", 
        "max_listening_connections",
        "failed_login_rate", 
        "suspicious_event_rate",
        "process_creation_rate"
    ]

    # Ensure all columns exist and fill missing values with 0
    for col in ml_features:
        if col not in df.columns:
            df[col] = 0.0
            
    X = df[ml_features].fillna(0.0)

    print(f"[*] Training Isolation Forest on {len(X)} system snapshots...")
    
    # Initialize the model
    # contamination=0.05 means we assume 5% of the training data might be anomalies
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)

    # Save the trained model
    joblib.dump(model, MODEL_OUTPUT)
    print(f"[+] Model successfully trained and saved to: {MODEL_OUTPUT}")

if __name__ == "__main__":
    train_model()