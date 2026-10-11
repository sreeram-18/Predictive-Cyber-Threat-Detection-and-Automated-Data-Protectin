"""
network_feature_mapper.py

Converts real-time network behaviour windows into:
1. Complete 41-feature NSL-KDD numerical feature vectors ready for ML inference
2. Real-time structured telemetry log (ml_network_features.jsonl)
"""

import json
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(BASE_DIR, "Processing", "network_windows.jsonl")
OUTPUT_FILE = os.path.join(BASE_DIR, "Processing", "ml_network_features.jsonl")

# ------------------------------------------------------------------
# NSL-KDD CATEGORICAL ENCODING DICTIONARIES
# ------------------------------------------------------------------

PROTOCOLS = ["tcp", "udp", "icmp", "unknown"]
SERVICES = ["http", "https", "dns", "smtp", "ftp", "ssh", "rdp", "smb", "unknown"]
FLAGS = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "S2", "S3", "OTH"]

SERVICE_FIELDS = {
    "https": ("https_flow_count", "https_flows"),
    "http": ("http_flow_count", "http_flows"),
    "dns": ("dns_flow_count", "dns_flows"),
    "ssh": ("ssh_flow_count", "ssh_flows"),
    "rdp": ("rdp_flow_count", "rdp_flows"),
    "smb": ("smb_flow_count", "smb_flows"),
}

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

def clamp(value, minimum=0.0, maximum=1.0):
    return max(minimum, min(maximum, value))

def first_value(data, *names, default=None):
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return default

def determine_protocol(window):
    tcp = safe_int(first_value(window, "tcp_flow_count", "tcp_flows", default=0))
    udp = safe_int(first_value(window, "udp_flow_count", "udp_flows", default=0))
    icmp = safe_int(first_value(window, "icmp_flow_count", "icmp_flows", default=0))

    counts = {"tcp": tcp, "udp": udp, "icmp": icmp}
    if sum(counts.values()) <= 0:
        return "unknown"
    return max(counts, key=counts.get)

def determine_service(window):
    counts = {}
    for service, fields in SERVICE_FIELDS.items():
        count = safe_int(first_value(window, *fields, default=0))
        if count > 0:
            counts[service] = count

    services = window.get("services")
    if isinstance(services, dict):
        for service, count in services.items():
            s_name = str(service).strip().lower()
            cnt = safe_int(count)
            if cnt > 0:
                counts[s_name] = max(counts.get(s_name, 0), cnt)

    if not counts:
        return "unknown"
    return max(counts, key=counts.get)

def determine_flag(window):
    flow_count = safe_int(window.get("flow_count", 0))
    if flow_count <= 0:
        return "OTH"

    syn_flows = safe_int(first_value(window, "syn_flow_count", "flows_with_syn", default=0))
    rst_flows = safe_int(first_value(window, "rst_flow_count", "flows_with_rst", default=0))
    fin_flows = safe_int(first_value(window, "fin_flow_count", "flows_with_fin", default=0))
    ack_count = safe_int(window.get("ack_count", 0))
    rst_count = safe_int(window.get("rst_count", 0))

    if rst_flows > 0 and syn_flows > 0:
        return "REJ"
    if syn_flows > 0:
        return "SF" if ack_count > 0 else "S0"
    if fin_flows > 0 or ack_count > 0:
        return "SF"
    if rst_count > 0:
        return "RSTO"
    return "OTH"

def build_nsl_kdd_vector(record):
    """Encodes record fields into numerical vector for scikit-learn models."""
    return [
        safe_float(record["duration"]),
        record["protocol_type"],  # Passed as string for OneHotEncoder
        record["service"],        # Passed as string for OneHotEncoder
        record["flag"],           # Passed as string for OneHotEncoder
        safe_int(record["src_bytes"]),
        safe_int(record["dst_bytes"]),
        0,  # land
        0,  # wrong_fragment
        safe_int(record["urgent"]),
        0,  # hot
        0,  # num_failed_logins
        0,  # logged_in
        0,  # num_compromised
        0,  # root_shell
        0,  # su_attempted
        0,  # num_root
        0,  # num_file_creations
        0,  # num_shells
        0,  # num_access_files
        0,  # num_outbound_cmds
        0,  # is_host_login
        0,  # is_guest_login
        safe_int(record["count"]),
        safe_int(record["srv_count"]),
        safe_float(record["serror_rate"]),
        0.0, # srv_serror_rate
        safe_float(record["rerror_rate"]),
        0.0, # srv_rerror_rate
        safe_float(record["same_srv_rate"]),
        safe_float(record["diff_srv_rate"]),
        0.0, # srv_diff_host_rate
        safe_int(record["dst_host_count"]),
        0,   # dst_host_srv_count
        0.0, # dst_host_same_srv_rate
        0.0, # dst_host_diff_srv_rate
        0.0, # dst_host_same_src_port_rate
        0.0, # dst_host_srv_diff_host_rate
        0.0, # dst_host_serror_rate
        0.0, # dst_host_srv_serror_rate
        0.0, # dst_host_rerror_rate
        0.0  # dst_host_srv_rerror_rate
    ]

def map_window(window):
    flow_count = safe_int(window.get("flow_count", 0))
    forward_bytes = safe_int(window.get("forward_bytes", 0))
    backward_bytes = safe_int(window.get("backward_bytes", 0))
    avg_duration = safe_float(first_value(window, "avg_flow_duration", "average_flow_duration", default=0.0))

    protocol_type = determine_protocol(window)
    service = determine_service(window)
    flag = determine_flag(window)

    syn_flow_count = safe_int(first_value(window, "syn_flow_count", "flows_with_syn", default=0))
    rst_flow_count = safe_int(first_value(window, "rst_flow_count", "flows_with_rst", default=0))

    serror_rate = clamp(safe_rate(syn_flow_count, flow_count))
    rerror_rate = clamp(safe_rate(rst_flow_count, flow_count))

    srv_count = safe_int(window.get("service_distribution", {}).get(service, 0)) if service != "unknown" else 0
    same_srv_rate = clamp(safe_rate(srv_count, flow_count))
    diff_srv_rate = clamp(1.0 - same_srv_rate) if flow_count > 0 else 0.0

    raw_record = {
        "window_start": window.get("window_start"),
        "window_end": window.get("window_end"),
        "duration": avg_duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": forward_bytes,
        "dst_bytes": backward_bytes,
        "urgent": safe_int(window.get("urg_count", 0)),
        "count": flow_count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "rerror_rate": rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "dst_host_count": safe_int(window.get("unique_destination_ips", 0)),
    }

    # Generate the vector expected by realtime_detector.py
    raw_record["features"] = build_nsl_kdd_vector(raw_record)
    return raw_record

def start_streaming_mapper():
    print("==========================================")
    print("      NETWORK FEATURE MAPPER (STREAMING)")
    print("==========================================")
    print(f"Input file  : {INPUT_FILE}")
    print(f"Output file : {OUTPUT_FILE}\n")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Wait for input file creation
    while not os.path.exists(INPUT_FILE):
        print("[!] Waiting for Processing/network_windows.jsonl...")
        time.sleep(2)

    print("[*] Tailing network_windows.jsonl for new entries...\n")
    
    with open(INPUT_FILE, "r", encoding="utf-8") as in_file, \
         open(OUTPUT_FILE, "a", encoding="utf-8") as out_file:
        
        while True:
            line = in_file.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                window = json.loads(line.strip())
                if isinstance(window, dict):
                    mapped = map_window(window)
                    out_file.write(json.dumps(mapped) + "\n")
                    out_file.flush()  # IMMEDIATE DISK FLUSH FOR REAL-TIME PIPELINES
                    print(f"[{mapped['window_end']}] Mapped window -> Feature vector generated.")
            except Exception as e:
                print(f"[!] Error mapping window: {e}")

if __name__ == "__main__":
    start_streaming_mapper()