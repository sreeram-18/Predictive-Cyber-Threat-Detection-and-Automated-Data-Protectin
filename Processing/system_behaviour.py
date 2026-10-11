"""
system_behaviour_2.py (Real-Time Streaming)

Combines:
    - Windows Security/System event logs
    - System resource snapshots

into fixed time-based behaviour windows and flushes them continuously.
"""

import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENT_LOG_FILE = os.path.join(BASE_DIR, "Collectors", "event_logs.jsonl")
SYSTEM_FILE = os.path.join(BASE_DIR, "Collectors", "system_events.jsonl")
OUTPUT_FILE = os.path.join(BASE_DIR, "Processing", "system_windows.jsonl")
WINDOW_SIZE = 30


# ============================================================
# EVENT ID DEFINITIONS
# ============================================================

SUCCESSFUL_LOGON_IDS = {4624}
FAILED_LOGON_IDS = {4625}
LOGOFF_IDS = {4634, 4647}
PRIVILEGE_IDS = {4672}
PROCESS_CREATION_IDS = {4688}
ACCOUNT_CREATION_IDS = {4720}
ACCOUNT_DELETION_IDS = {4726}
GROUP_CHANGE_IDS = {4728, 4729, 4732, 4733, 4756, 4757}
SERVICE_INSTALLATION_IDS = {4697}


# ============================================================
# HELPERS
# ============================================================

def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def safe_rate(numerator, denominator):
    if denominator <= 0:
        return 0.0
    return numerator / denominator

def parse_timestamp(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    value = str(value).strip()
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def get_event_id(record):
    possible_fields = ["event_id", "EventID", "eventId", "id"]
    for field in possible_fields:
        if field in record:
            value = record[field]
            if isinstance(value, dict):
                value = value.get("id", value.get("value"))
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    return None

def get_timestamp(record):
    possible_fields = ["timestamp", "time", "TimeCreated", "event_time", "datetime"]
    for field in possible_fields:
        if field in record:
            parsed = parse_timestamp(record[field])
            if parsed:
                return parsed
    return None


# ============================================================
# EVENT CLASSIFICATION
# ============================================================

def classify_event(record):
    event_id = get_event_id(record)

    if event_id in SUCCESSFUL_LOGON_IDS: return "successful_logon"
    if event_id in FAILED_LOGON_IDS: return "failed_logon"
    if event_id in LOGOFF_IDS: return "logoff"
    if event_id in PRIVILEGE_IDS: return "privilege"
    if event_id in PROCESS_CREATION_IDS: return "process_creation"
    if event_id in ACCOUNT_CREATION_IDS: return "account_creation"
    if event_id in ACCOUNT_DELETION_IDS: return "account_deletion"
    if event_id in GROUP_CHANGE_IDS: return "group_change"
    if event_id in SERVICE_INSTALLATION_IDS: return "service_installation"

    event_text = ""
    for field in ["event_type", "type", "EventType", "description", "message"]:
        value = record.get(field)
        if value:
            event_text += " " + str(value).lower()

    if any(x in event_text for x in ["successful logon", "successful login", "logon success", "login success"]):
        return "successful_logon"
    if any(x in event_text for x in ["failed logon", "failed login", "logon failure", "login failure"]):
        return "failed_logon"
    if "logoff" in event_text or "logged off" in event_text:
        return "logoff"
    if "special privileges" in event_text or "privilege" in event_text:
        return "privilege"
    if "process creation" in event_text or "new process" in event_text:
        return "process_creation"

    return "other"


# ============================================================
# EXTRACT EVENT INFORMATION
# ============================================================

def extract_user(record):
    for field in ["user", "username", "User", "account_name", "AccountName", "target_user"]:
        value = record.get(field)
        if value:
            value = str(value).strip()
            if value and value.lower() not in {"none", "null", "unknown"}:
                return value
    return None

def extract_source_ip(record):
    for field in ["source_ip", "SourceIP", "src_ip", "source_address", "SourceAddress", "ip_address"]:
        value = record.get(field)
        if value:
            value = str(value).strip()
            if value and value.lower() not in {"none", "null", "unknown"}:
                return value
    return None


# ============================================================
# WINDOW KEY & CREATION
# ============================================================

def get_window_start(timestamp):
    timestamp_seconds = timestamp.timestamp()
    window_seconds = (int(timestamp_seconds) // WINDOW_SIZE) * WINDOW_SIZE
    return datetime.fromtimestamp(window_seconds, tz=timezone.utc)

def create_window(window_start):
    window_end = window_start.timestamp() + WINDOW_SIZE
    window_end = datetime.fromtimestamp(window_end, tz=timezone.utc)
    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "event_record_count": 0,
        "successful_logins": 0,
        "num_failed_logins": 0,
        "logoff_count": 0,
        "privilege_event_count": 0,
        "process_creation_count": 0,
        "account_creation_count": 0,
        "account_deletion_count": 0,
        "group_change_count": 0,
        "service_installation_count": 0,
        "users": set(),
        "source_ips": set(),
        "system_snapshot_count": 0,
        "cpu_values": [],
        "memory_values": [],
        "disk_values": [],
        "process_values": [],
        "high_cpu_process_values": [],
        "network_connection_values": [],
        "established_connection_values": [],
        "listening_connection_values": [],
        "active_user_values": []
    }


# ============================================================
# ADD EVENTS & SNAPSHOTS TO WINDOW
# ============================================================

def add_event(window, record):
    window["event_record_count"] += 1
    event_type = classify_event(record)

    if event_type == "successful_logon": window["successful_logins"] += 1
    elif event_type == "failed_logon": window["num_failed_logins"] += 1
    elif event_type == "logoff": window["logoff_count"] += 1
    elif event_type == "privilege": window["privilege_event_count"] += 1
    elif event_type == "process_creation": window["process_creation_count"] += 1
    elif event_type == "account_creation": window["account_creation_count"] += 1
    elif event_type == "account_deletion": window["account_deletion_count"] += 1
    elif event_type == "group_change": window["group_change_count"] += 1
    elif event_type == "service_installation": window["service_installation_count"] += 1

    user = extract_user(record)
    if user: window["users"].add(user)

    source_ip = extract_source_ip(record)
    if source_ip: window["source_ips"].add(source_ip)


def get_snapshot_value(record, possible_fields, default=0.0):
    for field in possible_fields:
        if field in record:
            return safe_float(record[field], default)
    return default

def add_system_snapshot(window, record):
    window["system_snapshot_count"] += 1
    window["cpu_values"].append(get_snapshot_value(record, ["cpu_percent", "cpu_usage", "cpu"]))
    window["memory_values"].append(get_snapshot_value(record, ["memory_percent", "memory"]))
    window["disk_values"].append(get_snapshot_value(record, ["disk_percent", "disk"]))
    window["process_values"].append(get_snapshot_value(record, ["process_count", "processes"]))
    window["high_cpu_process_values"].append(get_snapshot_value(record, ["high_cpu_process_count", "high_cpu"]))
    window["network_connection_values"].append(get_snapshot_value(record, ["network_connection_count", "network_connections"]))
    window["established_connection_values"].append(get_snapshot_value(record, ["established_connection_count"]))
    window["listening_connection_values"].append(get_snapshot_value(record, ["listening_connection_count"]))
    window["active_user_values"].append(get_snapshot_value(record, ["active_user_count", "active_users"]))


# ============================================================
# AVERAGES & FINALIZATION
# ============================================================

def average(values):
    return sum(values) / len(values) if values else 0.0

def maximum(values):
    return max(values) if values else 0.0

def finalize_window(window):
    event_count = window["event_record_count"]
    successful_logins = window["successful_logins"]
    failed_logins = window["num_failed_logins"]
    privileges = window["privilege_event_count"]

    logged_in = 1 if successful_logins > 0 else 0
    is_host_login = 1 if successful_logins > 0 else 0
    
    is_guest_login = 0
    for user in window["users"]:
        if user.lower() == "guest":
            is_guest_login = 1
            break

    suspicious_event_count = (
        failed_logins + privileges + window["account_creation_count"] + 
        window["account_deletion_count"] + window["group_change_count"] + 
        window["service_installation_count"]
    )

    result = {
        "window_start": window["window_start"],
        "window_end": window["window_end"],
        "event_record_count": event_count,
        "successful_logins": successful_logins,
        "num_failed_logins": failed_logins,
        "logoff_count": window["logoff_count"],
        "privilege_event_count": privileges,
        "process_creation_count": window["process_creation_count"],
        "account_creation_count": window["account_creation_count"],
        "account_deletion_count": window["account_deletion_count"],
        "group_change_count": window["group_change_count"],
        "service_installation_count": window["service_installation_count"],
        "unique_users": len(window["users"]),
        "unique_source_ips": len(window["source_ips"]),
        "logged_in": logged_in,
        "num_root": privileges,
        "is_host_login": is_host_login,
        "is_guest_login": is_guest_login,
        "system_snapshot_count": window["system_snapshot_count"],
        "avg_cpu_percent": average(window["cpu_values"]),
        "max_cpu_percent": maximum(window["cpu_values"]),
        "avg_memory_percent": average(window["memory_values"]),
        "max_memory_percent": maximum(window["memory_values"]),
        "avg_disk_percent": average(window["disk_values"]),
        "max_disk_percent": maximum(window["disk_values"]),
        "avg_process_count": average(window["process_values"]),
        "max_process_count": maximum(window["process_values"]),
        "avg_high_cpu_processes": average(window["high_cpu_process_values"]),
        "max_high_cpu_processes": maximum(window["high_cpu_process_values"]),
        "avg_network_connections": average(window["network_connection_values"]),
        "max_network_connections": maximum(window["network_connection_values"]),
        "avg_established_connections": average(window["established_connection_values"]),
        "max_established_connections": maximum(window["established_connection_values"]),
        "avg_listening_connections": average(window["listening_connection_values"]),
        "max_listening_connections": maximum(window["listening_connection_values"]),
        "avg_active_users": average(window["active_user_values"]),
        "failed_login_rate": safe_rate(failed_logins, event_count),
        "privilege_event_rate": safe_rate(privileges, event_count),
        "process_creation_rate": safe_rate(window["process_creation_count"], event_count),
        "suspicious_event_count": suspicious_event_count,
        "suspicious_event_rate": safe_rate(suspicious_event_count, event_count),
        "system_snapshot_available": window["system_snapshot_count"] > 0
    }
    return result


# ============================================================
# REAL-TIME STREAMING PIPELINE
# ============================================================

def tail_file(filename, file_position):
    """Safely reads only new lines from a file since the last position."""
    records = []
    if not os.path.exists(filename):
        return records, file_position

    try:
        with open(filename, "r", encoding="utf-8") as f:
            f.seek(file_position)
            while True:
                current_pos = f.tell()
                line = f.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    f.seek(current_pos)
                    break
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return records, f.tell()
    except Exception:
        return records, file_position

def start_streaming_behaviour():
    print("==========================================")
    print("   SYSTEM BEHAVIOUR PROCESSOR (STREAMING) ")
    print("==========================================")
    print(f"Monitoring  : {EVENT_LOG_FILE}")
    print(f"Monitoring  : {SYSTEM_FILE}")
    print(f"Output      : {OUTPUT_FILE}")
    print("------------------------------------------")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    event_pos = 0
    system_pos = 0
    active_windows = {}

    while True:
        try:
            # 1. Read new events from both files
            events, event_pos = tail_file(EVENT_LOG_FILE, event_pos)
            systems, system_pos = tail_file(SYSTEM_FILE, system_pos)

            # 2. Add Windows Events to their respective time windows
            for record in events:
                ts = get_timestamp(record)
                if not ts: continue
                w_start = get_window_start(ts)
                key = w_start.isoformat()
                if key not in active_windows:
                    active_windows[key] = create_window(w_start)
                add_event(active_windows[key], record)

            # 3. Add psutil System Telemetry to time windows
            for record in systems:
                ts = get_timestamp(record)
                if not ts: continue
                w_start = get_window_start(ts)
                key = w_start.isoformat()
                if key not in active_windows:
                    active_windows[key] = create_window(w_start)
                add_system_snapshot(active_windows[key], record)

            # 4. Flush windows that have expired (older than current time)
            now = datetime.now(timezone.utc)
            to_remove = []

            for key, window in active_windows.items():
                w_end = datetime.fromisoformat(window["window_end"])
                # Add a 2-second buffer to allow late logs to arrive
                if (now - w_end).total_seconds() > 2:
                    finalized = finalize_window(window)
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                        out.write(json.dumps(finalized, ensure_ascii=False) + "\n")
                        out.flush()  # Force write to disk immediately
                    
                    print(f"[{window['window_end']}] System Window Closed | Events: {window['event_record_count']} | Snapshots: {window['system_snapshot_count']}")
                    to_remove.append(key)

            for key in to_remove:
                del active_windows[key]

            time.sleep(2)

        except KeyboardInterrupt:
            print("\nStopping streaming system behaviour...")
            break
        except Exception as e:
            print(f"[!] Error processing system behaviour: {e}")
            time.sleep(2)

if __name__ == "__main__":
    start_streaming_behaviour()