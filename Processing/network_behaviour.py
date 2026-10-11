import json
import os
import time
from datetime import datetime
from collections import Counter


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Flexible lookup: search Collectors/network_flows.jsonl OR same directory
FLOW_FILE = os.path.join(BASE_DIR, "Collectors", "network_flows.jsonl")
if not os.path.exists(FLOW_FILE):
    FLOW_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_flows.jsonl")

OUTPUT_FILE = os.path.join(BASE_DIR, "Processing", "network_windows.jsonl")

WINDOW_SIZE = 10          # Seconds
POLL_INTERVAL = 2         # Seconds


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


def safe_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    return bool(value)


def safe_rate(numerator, denominator):
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def parse_timestamp(value):
    if not value:
        return None
    try:
        value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


# ============================================================
# SAFE FILE READER
# ============================================================

def read_new_flows(file_position):
    flows = []
    if not os.path.exists(FLOW_FILE):
        return flows, file_position

    try:
        with open(FLOW_FILE, "r", encoding="utf-8") as f:
            f.seek(file_position)

            while True:
                current_pos = f.tell()
                line = f.readline()

                if not line:
                    break

                # Prevent dropping partial json lines during active writes
                if not line.endswith("\n"):
                    f.seek(current_pos)
                    break

                line = line.strip()
                if not line:
                    continue

                try:
                    flow = json.loads(line)
                    if isinstance(flow, dict) and flow.get("flow_id"):
                        flows.append(flow)
                except json.JSONDecodeError:
                    continue

            new_position = f.tell()
        return flows, new_position

    except Exception as e:
        print(f"[ERROR] Could not read flow file: {e}")
        return [], file_position


# ============================================================
# FLOW NORMALIZATION
# ============================================================

def normalize_flow(flow):
    start_time = parse_timestamp(flow.get("start_time"))
    end_time = parse_timestamp(flow.get("end_time"))

    if start_time is None:
        return None

    packet_count = safe_int(flow.get("packet_count"))
    forward_packets = safe_int(flow.get("forward_packets"))
    backward_packets = safe_int(flow.get("backward_packets"))

    # Ensure aggregate matches flow breakdown
    if packet_count == 0 and (forward_packets > 0 or backward_packets > 0):
        packet_count = forward_packets + backward_packets

    forward_bytes = safe_int(flow.get("forward_bytes"))
    backward_bytes = safe_int(flow.get("backward_bytes"))
    total_bytes = safe_int(flow.get("total_bytes"))

    if total_bytes == 0 and (forward_bytes > 0 or backward_bytes > 0):
        total_bytes = forward_bytes + backward_bytes

    duration = safe_float(flow.get("duration"))
    if duration <= 0 and end_time is not None:
        duration = max(0.0, (end_time - start_time).total_seconds())

    return {
        "flow_id": flow.get("flow_id"),
        "start_time": start_time,
        "end_time": end_time,
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "src_port": safe_int(flow.get("src_port")),
        "dst_port": safe_int(flow.get("dst_port")),
        "protocol": str(flow.get("protocol", "UNKNOWN")),
        "service": str(flow.get("service", "UNKNOWN")),
        "packet_count": packet_count,
        "forward_packets": forward_packets,
        "backward_packets": backward_packets,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,
        "total_bytes": total_bytes,
        "min_packet_size": safe_int(flow.get("min_packet_size")),
        "max_packet_size": safe_int(flow.get("max_packet_size")),
        "syn_count": safe_int(flow.get("syn_count")),
        "ack_count": safe_int(flow.get("ack_count")),
        "fin_count": safe_int(flow.get("fin_count")),
        "rst_count": safe_int(flow.get("rst_count")),
        "psh_count": safe_int(flow.get("psh_count")),
        "urg_count": safe_int(flow.get("urg_count")),
        "is_tcp": safe_bool(flow.get("is_tcp")),
        "is_udp": safe_bool(flow.get("is_udp")),
        "is_icmp": safe_bool(flow.get("is_icmp")),
        "is_single_packet": safe_bool(flow.get("is_single_packet")),
        "has_syn": safe_bool(flow.get("has_syn")),
        "has_rst": safe_bool(flow.get("has_rst")),
        "has_fin": safe_bool(flow.get("has_fin")),
        "duration": duration,
    }


# ============================================================
# WINDOW FEATURE COMPUTATION
# ============================================================

def create_window(flows, window_start, window_end):
    if not flows:
        return None

    total_flows = len(flows)
    tcp_flows = sum(1 for f in flows if f["is_tcp"])
    udp_flows = sum(1 for f in flows if f["is_udp"])
    icmp_flows = sum(1 for f in flows if f["is_icmp"])

    source_ips = {f["src_ip"] for f in flows if f["src_ip"]}
    destination_ips = {f["dst_ip"] for f in flows if f["dst_ip"]}
    source_ports = {f["src_port"] for f in flows if f["src_port"] > 0}
    destination_ports = {f["dst_port"] for f in flows if f["dst_port"] > 0}

    services = Counter(f["service"] for f in flows)

    forward_packets = sum(f["forward_packets"] for f in flows)
    backward_packets = sum(f["backward_packets"] for f in flows)
    total_packets = sum(f["packet_count"] for f in flows)
    if total_packets == 0:
        total_packets = forward_packets + backward_packets

    forward_bytes = sum(f["forward_bytes"] for f in flows)
    backward_bytes = sum(f["backward_bytes"] for f in flows)
    total_bytes = sum(f["total_bytes"] for f in flows)
    if total_bytes == 0:
        total_bytes = forward_bytes + backward_bytes

    durations = [f["duration"] for f in flows]
    average_duration = safe_rate(sum(durations), len(durations))

    # Calculate average packet size accurately across total bytes and packets
    average_packet_size = safe_rate(total_bytes, total_packets)

    min_packet_size = min((f["min_packet_size"] for f in flows if f["min_packet_size"] > 0), default=0)
    max_packet_size = max((f["max_packet_size"] for f in flows if f["max_packet_size"] > 0), default=0)

    syn_count = sum(f["syn_count"] for f in flows)
    ack_count = sum(f["ack_count"] for f in flows)
    fin_count = sum(f["fin_count"] for f in flows)
    rst_count = sum(f["rst_count"] for f in flows)
    psh_count = sum(f["psh_count"] for f in flows)
    urg_count = sum(f["urg_count"] for f in flows)

    flows_with_syn = sum(1 for f in flows if f["has_syn"])
    flows_with_rst = sum(1 for f in flows if f["has_rst"])
    flows_with_fin = sum(1 for f in flows if f["has_fin"])
    single_packet_flows = sum(1 for f in flows if f["is_single_packet"])

    actual_window_seconds = max(0.001, (window_end - window_start).total_seconds())

    # Correct NSL-KDD rate bounds
    most_common_srv_cnt = services.most_common(1)[0][1] if services else 0
    same_service_rate = safe_rate(most_common_srv_cnt, total_flows)
    syn_rate = safe_rate(flows_with_syn, total_flows)
    rst_rate = safe_rate(flows_with_rst, total_flows)

    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "window_duration": actual_window_seconds,

        "flow_count": total_flows,
        "tcp_flows": tcp_flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,
        "flows_per_second": safe_rate(total_flows, actual_window_seconds),

        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "unique_source_ports": len(source_ports),
        "unique_destination_ports": len(destination_ports),

        "total_packets": total_packets,
        "forward_packets": forward_packets,
        "backward_packets": backward_packets,
        "packets_per_second": safe_rate(total_packets, actual_window_seconds),

        "total_bytes": total_bytes,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,
        "bytes_per_second": safe_rate(total_bytes, actual_window_seconds),

        "average_flow_duration": average_duration,
        "average_packet_size": average_packet_size,
        "minimum_packet_size": min_packet_size,
        "maximum_packet_size": max_packet_size,

        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,

        "syn_rate": syn_rate,
        "rst_rate": rst_rate,
        "same_service_rate": same_service_rate,

        "single_packet_flows": single_packet_flows,
        "service_count": len(services),
        "services": dict(services)
    }


def save_window(window):
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(window, separators=(",", ":")) + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write network window: {e}")


def run():
    print("==========================================")
    print("   NETWORK BEHAVIOUR MONITOR STARTED")
    print("==========================================")
    print(f"Flow file    : {FLOW_FILE}")
    print(f"Output file  : {OUTPUT_FILE}")
    print("------------------------------------------")

    file_position = 0
    current_flows = []
    window_start = datetime.now()

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            flows, new_position = read_new_flows(file_position)

            if flows:
                normalized = [f for f in (normalize_flow(fl) for fl in flows) if f is not None]
                current_flows.extend(normalized)
                file_position = new_position

            now = datetime.now()
            if (now - window_start).total_seconds() >= WINDOW_SIZE:
                if current_flows:
                    window = create_window(current_flows, window_start, now)
                    if window:
                        save_window(window)
                        print(f"[WINDOW SAVED] {window['window_start']} -> {window['window_end']} | "
                              f"Flows: {window['flow_count']} | Packets: {window['total_packets']}")
                    current_flows = []
                window_start = now

    except KeyboardInterrupt:
        print("\nStopping network behaviour monitor...")


if __name__ == "__main__":
    run()