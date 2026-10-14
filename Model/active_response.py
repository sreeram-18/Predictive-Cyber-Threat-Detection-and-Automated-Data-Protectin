import json
import time
import psutil
import subprocess
from datetime import datetime
from pathlib import Path

ALERTS_FILE = Path(__file__).resolve().parent.parent / "Processing" / "alerts.jsonl"

# SAFETY SHIELD
WHITELIST = [
    "explorer.exe", "svchost.exe", "System", "System Idle Process", 
    "python.exe", "node.exe", "cmd.exe", "powershell.exe", "Code.exe", 
    "SearchHost.exe", "Taskmgr.exe", "MsMpEng.exe"
]

def log_ips_action(module, message):
    """Writes the IPS action back to the alerts file so the Node.js backend sends it to React."""
    record = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": f"IPS {module}",
        "status": message,
        "is_anomaly": False, # False so the IPS doesn't trigger itself in an infinite loop
        "is_mitigation": True,
        "confidence": 100
    }
    try:
        with open(ALERTS_FILE, "a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")
    except Exception as e:
        print(f"[!] Could not write IPS log: {e}")

def mitigate_system_threat():
    print("[*] Initiating Lightning Process Hunt...")
    
    procs = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
            procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    time.sleep(1)
    
    target_proc = None
    max_cpu = 0.0
    
    for proc in procs:
        try:
            p_name = proc.info['name']
            if p_name and p_name not in WHITELIST:
                cpu = proc.cpu_percent(interval=None)
                if cpu > max_cpu:
                    max_cpu = cpu
                    target_proc = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    if target_proc and max_cpu > 3.0:
        try:
            p_name = target_proc.info['name']
            p_pid = target_proc.info['pid']
            
            target_proc.terminate()
            msg = f"Terminated {p_name} (PID {p_pid}) at {max_cpu}% CPU"
            print(f"[🛡️ IPS ACTION] {msg}")
            log_ips_action("Process Terminator", msg)
            
        except Exception as e:
            print(f"[!] Could not terminate {target_proc.info['name']}: {e}")
    else:
        print(f"[*] Mitigation complete: No rogue processes found (Highest CPU was {max_cpu}%).")

def mitigate_network_threat():
    print("[*] Initiating Network Block...")
    ATTACKER_IP = "192.168.1.254" 
    rule_name = f"SIEM_BLOCK_{ATTACKER_IP.replace('.', '_')}"
    
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule", 
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ATTACKER_IP}"
        ], capture_output=True, check=True)
        msg = f"Injected Firewall Block for IP {ATTACKER_IP}"
        print(f"[🛡️ IPS ACTION] {msg}")
        log_ips_action("Firewall Manager", msg)
        
    except subprocess.CalledProcessError:
        print(f"[!] Firewall block failed. Ensure terminal is Admin.")

def start_active_response():
    print("==========================================")
    print("    🛡️ ACTIVE RESPONSE ENGINE (IPS) ACTIVE")
    print("==========================================")
    
    while not ALERTS_FILE.exists():
        time.sleep(2)
        
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            try:
                alert = json.loads(line.strip())
                # Only trigger on actual anomalies, completely ignore our own mitigation logs
                if alert.get("is_anomaly") and not alert.get("is_mitigation"):
                    source = alert.get("source", "")
                    
                    if source == "System ML":
                        print(f"\n[!] Mitigation Triggered by: {alert.get('status')}")
                        mitigate_system_threat()
                        
                    elif source == "Network ML":
                        print(f"\n[!] Mitigation Triggered by: {alert.get('status')}")
                        mitigate_network_threat()
                        
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    start_active_response()