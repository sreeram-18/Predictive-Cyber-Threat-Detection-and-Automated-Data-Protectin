import json
import warnings
import time
import joblib
import warnings
import pandas as pd
import numpy as np
from pathlib import Path

# Silence scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

MODEL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODEL_DIR.parent
MODEL_PATH = MODEL_DIR / "nsl_kdd_random_forest_binary.pkl"
FEATURES_LOG = PROJECT_ROOT / "Processing" / "ml_network_features.jsonl"

# Standard 41 NSL-KDD column names
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

def load_detection_model():
    if not MODEL_PATH.exists():
        fallback = MODEL_DIR / "nsl_kdd_random_forest_78_baseline.pkl"
        if fallback.exists():
            print(f"[*] Loading fallback baseline model: {fallback.name}")
            return joblib.load(fallback)
        raise FileNotFoundError(f"Neither model file found in {MODEL_DIR}")
    
    print(f"[*] Loading primary binary model: {MODEL_PATH.name}")
    return joblib.load(MODEL_PATH)

def start_realtime_detection():
    model = load_detection_model()
    print(f"[*] Monitoring live features in: {FEATURES_LOG}\n")

    while not FEATURES_LOG.exists():
        print("[!] Waiting for Processing/ml_network_features.jsonl...")
        time.sleep(2)

    with open(FEATURES_LOG, "r") as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                data = json.loads(line)
                
                feature_vector = data.get("features")
                if isinstance(feature_vector, dict):
                    feature_vector = list(feature_vector.values())
                elif not isinstance(feature_vector, list):
                    feature_vector = []

                # Ensure we have exactly 41 items
                while len(feature_vector) < 41:
                    feature_vector.append(0)
                feature_vector = feature_vector[:41]

                # Build a standard DataFrame. By default, pandas preserves 
                # strings/objects or floats natively without forcing numpy ufunc casting rules prematurely.
                X = pd.DataFrame([feature_vector], columns=NSL_KDD_COLUMNS)

                # Convert columns explicitly based on whether they are categorical fields or numeric
                categorical_cols = ["protocol_type", "service", "flag"]
                for col in NSL_KDD_COLUMNS:
                    if col in categorical_cols:
                        X[col] = X[col].astype(str)
                    else:
                        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0.0)

                prediction = model.predict(X)[0]
                confidence = model.predict_proba(X)[0] if hasattr(model, "predict_proba") else None

                prediction_val = 1 if prediction in (1, "anomaly", "1") else 0
                status = "⚠ ANOMALY DETECTED" if prediction_val else "✅ NORMAL"
                timestamp = data.get("window_end") or data.get("timestamp", "LIVE")
                conf_val = max(confidence) * 100 if confidence is not None else 0.0
                
                conf_str = f" | Confidence: {conf_val:.1f}%" if confidence is not None else ""
                print(f"[{timestamp}] Status: {status}{conf_str}")

                # --- Write the ML prediction to a shared alerts file for the dashboard ---
                alert_record = {
                    "timestamp": timestamp,
                    "source": "Network ML",
                    "status": status,
                    "is_anomaly": bool(prediction_val),
                    "confidence": round(conf_val, 1)
                }
                
                ALERTS_LOG = PROJECT_ROOT / "Processing" / "alerts.jsonl"
                with open(ALERTS_LOG, "a", encoding="utf-8") as af:
                    af.write(json.dumps(alert_record) + "\n")
            except Exception as e:
                print(f"[!] Error processing record: {e}")

if __name__ == "__main__":
    start_realtime_detection()