import os
import sys
import time
import json
import math
from pathlib import Path
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ============================================================
# ⚠️ HARDCODED AWS CONFIGURATION (For Local Testing Only)
# ============================================================
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "AKIASAJYQTTZGXFIZAS6")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "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")
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "siem-backup-prajwal-2026"

os.environ["AWS_ACCESS_KEY_ID"] = AWS_ACCESS_KEY
os.environ["AWS_SECRET_ACCESS_KEY"] = AWS_SECRET_KEY
s3_client = boto3.client("s3", region_name=AWS_REGION)

# ============================================================
# PATHS & CONFIGURATION
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERTS_FILE = PROJECT_ROOT / "Processing" / "alerts.jsonl"
BACKUPS_FILE = PROJECT_ROOT / "Processing" / "backups.jsonl" # NEW: Dedicated Backup Log

USER_HOME = Path.home()
PROTECTED_DIRS = [
    PROJECT_ROOT / "SensitiveData",
]

CANARY_FILENAMES = ["!00_canary_trap.docx"]
CANARY_SEED_TEXT = b"CONFIDENTIAL DATA FILE - CANARY HONEYPOT RECORD 2026."
backup_in_progress = False

def calculate_shannon_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read(65536)
        if not data: return 0.0
        byte_counts = [0] * 256
        for b in data: byte_counts[b] += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except Exception: return 0.0

def plant_canaries():
    canary_paths = set()
    for protected_dir in PROTECTED_DIRS:
        protected_dir.mkdir(parents=True, exist_ok=True)
        for fname in CANARY_FILENAMES:
            c_path = protected_dir / fname
            if not c_path.exists():
                with open(c_path, "wb") as f: f.write(CANARY_SEED_TEXT)
            canary_paths.add(str(c_path.resolve()))
    return canary_paths

def execute_emergency_backup(trigger_reason, triggered_file):
    global backup_in_progress
    if backup_in_progress: return
    backup_in_progress = True

    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"\n[🚨 RANSOMWARE TRIGGERED] {trigger_reason}")
    
    # Write to Alert Feed
    alert = {"timestamp": timestamp, "source": "Ransomware Engine", "status": f"RANSOMWARE DETECTED: {trigger_reason}", "is_anomaly": True, "confidence": 100}
    with open(ALERTS_FILE, "a", encoding="utf-8") as af: af.write(json.dumps(alert) + "\n")

    # Upload files and write to Backup Vault Feed
    for protected_dir in PROTECTED_DIRS:
        if not protected_dir.exists(): continue
        for root, _, files in os.walk(protected_dir):
            for file in files:
                if file in CANARY_FILENAMES: continue
                file_path = Path(root) / file
                s3_key = f"vault/{timestamp[:10]}_{int(time.time())}/{file}"
                try:
                    s3_client.upload_file(str(file_path), S3_BUCKET_NAME, str(s3_key).replace("\\", "/"))
                    print(f"[+] Successfully backed up: {file}")
                    
                    backup_record = {"timestamp": timestamp, "filename": file, "bucket": S3_BUCKET_NAME, "status": "SECURED IN AWS S3"}
                    with open(BACKUPS_FILE, "a", encoding="utf-8") as bf: bf.write(json.dumps(backup_record) + "\n")
                except Exception as e:
                    print(f"[!] Upload failed for {file}: {e}")

    backup_in_progress = False

class CanarySecurityHandler(FileSystemEventHandler):
    def __init__(self, canary_paths):
        self.canary_paths = canary_paths
    def check_threat(self, event_path):
        if str(Path(event_path).resolve()) in self.canary_paths:
            execute_emergency_backup("Canary Honeypot Tampered", event_path)
    def on_modified(self, event):
        if not event.is_directory: self.check_threat(event.src_path)

def start_canary_guard():
    print("[*] RANSOMWARE SHIELD ACTIVE")
    canary_paths = plant_canaries()
    event_handler = CanarySecurityHandler(canary_paths)
    observer = Observer()
    for p in PROTECTED_DIRS: observer.schedule(event_handler, str(p), recursive=True)
    observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_canary_guard()