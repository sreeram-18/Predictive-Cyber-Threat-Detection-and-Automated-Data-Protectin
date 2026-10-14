import warnings
# Silence all scikit-learn and joblib multithreading warnings globally
warnings.warn = lambda *args, **kwargs: None
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="sklearn")
warnings.filterwarnings("ignore", module="joblib")

import os
import json
import time
import pandas as pd
import joblib
from pathlib import Path

# Paths
MODEL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODEL_DIR.parent
INPUT_FILE = PROJECT_ROOT / "Processing" / "system_ml_features.jsonl"
OUTPUT_ALERTS = PROJECT_ROOT / "Processing" / "alerts.jsonl"
MODEL_FILE = MODEL_DIR / "system_anomaly_model.pkl"

ML_FEATURES = [
    "avg_cpu_percent", 
    "max_memory_percent", 
    "max_network_connections", 
    "max_listening_connections",
    "failed_login_rate", 
    "suspicious_event_rate",
    "process_creation_rate"
]

def start_system_detector():
    print("==========================================")
    print("      ML SYSTEM ANOMALY DETECTOR ACTIVE   ")
    print("==========================================")

    if not MODEL_FILE.exists():
        print(f"[!] ML Model not found at {MODEL_FILE}. Please run train_system_model.py first.")
        return

    # Load the trained Isolation Forest model
    model = joblib.load(MODEL_FILE)
    print("[*] System ML Model loaded successfully.")

    while not INPUT_FILE.exists():
        time.sleep(2)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        # Move to the end of the file to read only live data
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                window = json.loads(line.strip())
                
                # Extract features for prediction
                input_data = {feat: window.get(feat, 0.0) for feat in ML_FEATURES}
                df = pd.DataFrame([input_data])
                
                # Predict: 1 is Normal, -1 is Anomaly
                prediction = model.predict(df)[0]
                
                timestamp = window.get("window_end", "LIVE")
                
                if prediction == -1:
                    print(f"[{timestamp}] 🚨 ML SYSTEM ANOMALY DETECTED!")
                    
                    alert_record = {
                        "timestamp": timestamp,
                        "source": "System ML",
                        "status": "BEHAVIORAL ANOMALY DETECTED",
                        "is_anomaly": True,
                        "confidence": 95
                    }
                    
                    with open(OUTPUT_ALERTS, "a", encoding="utf-8") as out:
                        out.write(json.dumps(alert_record) + "\n")
                else:
                    print(f"[{timestamp}] ✅ System Normal")

            except Exception as e:
                print(f"[!] Error processing system record: {e}")

if __name__ == "__main__":
    start_system_detector()