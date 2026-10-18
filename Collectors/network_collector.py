import os
import json
import time
import hashlib
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

INTERFACE = None  # Set to specific interface string if needed, e.g., "eth0"
FLOW_TIMEOUT = 10  # Seconds of inactivity before finalizing flow

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "network_flows.jsonl")

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP"
}

COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "MSRPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
    139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC"
}


# ============================================================
# SHARED STATE & THREAD SAFETY LOCK
# ============================================================

flows = {}
flow_lock = threading.Lock()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_protocol_name(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if IP in packet:
        return PROTOCOL_NAMES.get(packet[IP].proto, f"OTHER-{packet[IP].proto}")
    return "UNKNOWN"


def get_service(src_port, dst_port):
    if dst_port in COMMON_SERVICES:
        return COMMON_SERVICES[dst_port]
    if src_port in COMMON_SERVICES:
        return COMMON_SERVICES[src_port]
    return "UNKNOWN"


def generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
    value = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}-{timestamp.timestamp()}"
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def get_flow_key(packet):
    if IP not in packet:
        return None

    ip = packet[IP]
    src_ip, dst_ip = ip.src, ip.dst
    src_port, dst_port = 0, 0
    protocol = get_protocol_name(packet)

    if TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)

    if endpoint_a <= endpoint_b:
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    return (dst_ip, dst_port, src_ip, src_port, protocol)


# ============================================================
# FLOW LIFECYCLE
# ============================================================

def create_flow(packet, timestamp):
    ip = packet[IP]
    src_ip, dst_ip = ip.src, ip.dst
    src_port, dst_port = 0, 0
    protocol = get_protocol_name(packet)

    if TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    flow_id = generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
    packet_size = len(packet)

    return {
        "flow_id": flow_id,
        "start_time": timestamp.isoformat(),
        "end_time": timestamp.isoformat(),
        "last_seen": timestamp.isoformat(),

        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,

        "protocol": protocol,
        "service": get_service(src_port, dst_port),

        "packet_count": 0,
        "forward_packets": 0,
        "backward_packets": 0,

        "forward_bytes": 0,
        "backward_bytes": 0,
        "total_bytes": 0,

        "min_packet_size": packet_size,
        "max_packet_size": packet_size,

        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "psh_count": 0,
        "urg_count": 0,

        "is_tcp": protocol == "TCP",
        "is_udp": protocol == "UDP",
        "is_icmp": protocol == "ICMP"
    }


def update_flow(flow, packet, timestamp):
    ip = packet[IP]
    packet_size = len(packet)

    flow["packet_count"] += 1
    flow["end_time"] = timestamp.isoformat()
    flow["last_seen"] = timestamp.isoformat()

    if ip.src == flow["src_ip"] and ip.dst == flow["dst_ip"]:
        flow["forward_packets"] += 1
        flow["forward_bytes"] += packet_size
    else:
        flow["backward_packets"] += 1
        flow["backward_bytes"] += packet_size

    # Maintain running packet size boundaries without unbounded arrays
    if flow["min_packet_size"] is None or packet_size < flow["min_packet_size"]:
        flow["min_packet_size"] = packet_size
    if flow["max_packet_size"] is None or packet_size > flow["max_packet_size"]:
        flow["max_packet_size"] = packet_size

    # Robust Scapy TCP flag string inspection
    if TCP in packet:
        flags = str(packet[TCP].flags)
        if "S" in flags: flow["syn_count"] += 1
        if "A" in flags: flow["ack_count"] += 1
        if "F" in flags: flow["fin_count"] += 1
        if "R" in flags: flow["rst_count"] += 1
        if "P" in flags: flow["psh_count"] += 1
        if "U" in flags: flow["urg_count"] += 1


def finalize_flow(flow):
    start = datetime.fromisoformat(flow["start_time"])
    end = datetime.fromisoformat(flow["end_time"])

    duration = max(0.0, (end - start).total_seconds())
    flow["duration"] = duration

    flow["total_bytes"] = flow["forward_bytes"] + flow["backward_bytes"]

    if flow["packet_count"] > 0:
        flow["average_packet_size"] = flow["total_bytes"] / flow["packet_count"]
    else:
        flow["average_packet_size"] = 0.0

    if duration > 0:
        flow["packets_per_second"] = flow["packet_count"] / duration
        flow["bytes_per_second"] = flow["total_bytes"] / duration
        flow["forward_bytes_per_second"] = flow["forward_bytes"] / duration
        flow["backward_bytes_per_second"] = flow["backward_bytes"] / duration
    else:
        flow["packets_per_second"] = 0.0
        flow["bytes_per_second"] = 0.0
        flow["forward_bytes_per_second"] = 0.0
        flow["backward_bytes_per_second"] = 0.0

    flow["is_single_packet"] = (flow["packet_count"] == 1)
    flow["has_syn"] = (flow["syn_count"] > 0)
    flow["has_rst"] = (flow["rst_count"] > 0)
    flow["has_fin"] = (flow["fin_count"] > 0)

    return flow


def save_flow(flow):
    finalized = finalize_flow(flow)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(finalized) + "\n")

    print(f"[FLOW COMPLETED] ID: {finalized['flow_id']} | "
          f"{finalized['src_ip']}:{finalized['src_port']} -> "
          f"{finalized['dst_ip']}:{finalized['dst_port']} | "
          f"Pkts: {finalized['packet_count']} | Duration: {finalized['duration']:.2f}s")


# ============================================================
# WORKERS
# ============================================================

def process_packet(packet):
    if IP not in packet:
        return

    # Use wire timestamp if present, fallback to system clock in UTC
    try:
        timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    except Exception:
        timestamp = datetime.now(timezone.utc)

    key = get_flow_key(packet)
    if key is None:
        return

    with flow_lock:
        if key not in flows:
            flows[key] = create_flow(packet, timestamp)
        update_flow(flows[key], packet, timestamp)


def cleanup_flows():
    while True:
        current_time = datetime.now(timezone.utc)
        expired_keys = []

        with flow_lock:
            for key, flow in list(flows.items()):
                last_seen = datetime.fromisoformat(flow["last_seen"])
                
                # Safely remove timezone info before subtracting
                current_naive = current_time.replace(tzinfo=None)
                last_naive = last_seen.replace(tzinfo=None)

                if (current_naive - last_naive).total_seconds() >= FLOW_TIMEOUT:
                    expired_keys.append(key)

            expired_flows = [flows.pop(k) for k in expired_keys]

        for flow in expired_flows:
            save_flow(flow)

        time.sleep(1)
    while True:
        current_time = datetime.now(timezone.utc)
        expired_keys = []

        with flow_lock:
            for key, flow in list(flows.items()):
                # Because last_seen now has +00:00, Python will parse it as aware
                last_seen = datetime.fromisoformat(flow["last_seen"])
                if (current_time - last_seen).total_seconds() >= FLOW_TIMEOUT:
                    expired_keys.append(key)

            expired_flows = [flows.pop(k) for k in expired_keys]

        for flow in expired_flows:
            save_flow(flow)

        time.sleep(1)
    while True:
        current_time = datetime.now()
        expired_keys = []

        with flow_lock:
            for key, flow in list(flows.items()):
                last_seen = datetime.fromisoformat(flow["last_seen"])
                # Safely strip timezone info from both variables before subtracting
                # Safely remove timezone info before subtracting
                current_naive = current_time.replace(tzinfo=None)
                last_naive = last_seen.replace(tzinfo=None)

                if (current_naive - last_naive).total_seconds() >= FLOW_TIMEOUT:
                    expired_keys.append(key)

            expired_flows = [flows.pop(k) for k in expired_keys]

        for flow in expired_flows:
            save_flow(flow)

        time.sleep(1)


def start_network_monitor():
    print("==========================================")
    print("     NETWORK MONITORING STARTED")
    print("==========================================")
    print(f"Interface      : {INTERFACE or 'Default'}")
    print(f"Flow timeout   : {FLOW_TIMEOUT} seconds")
    print(f"Output file    : {OUTPUT_FILE}")
    print("------------------------------------------")

    cleanup_thread = threading.Thread(target=cleanup_flows, daemon=True)
    cleanup_thread.start()

    sniff(iface=INTERFACE, prn=process_packet, store=False)


if __name__ == "__main__":
    try:
        start_network_monitor()
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        with flow_lock:
            remaining_flows = list(flows.values())
            flows.clear()

        for flow in remaining_flows:
            save_flow(flow)
        print("Network monitor stopped.")