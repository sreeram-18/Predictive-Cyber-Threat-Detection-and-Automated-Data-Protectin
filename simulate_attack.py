import json
import time
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
SYS_FILE = ROOT / "Processing" / "system_ml_features.jsonl"
NET_FILE = ROOT / "Processing" / "ml_network_features.jsonl"
ALERTS_FILE = ROOT / "Processing" / "alerts.jsonl"

ts = datetime.now().strftime("%H:%M:%S")

# 1. System Feature Injection
sys_record = {
    "window_end": ts,
    "avg_cpu_percent": 99.9,
    "max_memory_percent": 98.0,
    "max_network_connections": 5000,
    "max_listening_connections": 120,
    "failed_login_rate": 80.0,
    "suspicious_event_rate": 45.0,
    "process_creation_rate": 950.0
}
with open(SYS_FILE, "a", encoding="utf-8") as f:
    f.write(json.dumps(sys_record) + "\n")
print(f"[+] Wrote System feature window to {SYS_FILE}")

# 2. Network Feature Injection (Neptune SYN Flood format)
net_features = [
    0.0, "tcp", "http", "S0", 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 511, 511, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 255, 255, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0
]
net_record = {
    "window_end": ts,
    "timestamp": ts,
    "features": net_features
}
with open(NET_FILE, "a", encoding="utf-8") as f:
    f.write(json.dumps(net_record) + "\n")
print(f"[+] Wrote Network feature window to {NET_FILE}")

# 3. Direct Alert Feed Write (guarantees UI notification)
alerts = [
    {"timestamp": ts, "source": "Network ML", "status": "⚠ ANOMALY DETECTED", "is_anomaly": True, "confidence": 97.4},
    {"timestamp": ts, "source": "System ML", "status": "BEHAVIORAL ANOMALY DETECTED", "is_anomaly": True, "confidence": 94.8}
]
with open(ALERTS_FILE, "a", encoding="utf-8") as f:
    for a in alerts:
        f.write(json.dumps(a) + "\n")
print(f"[+] Direct alert written to {ALERTS_FILE}")
print("[*] Check your React frontend now!")