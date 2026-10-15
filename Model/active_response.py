import json
import time
import psutil
import subprocess
from datetime import datetime
from pathlib import Path

ALERTS_FILE = Path(__file__).resolve().parent.parent / "Processing" / "alerts.jsonl"

# The Whitelist is now our absolute failsafe
WHITELIST = [
    "explorer.exe", "svchost.exe", "System", "System Idle Process", 
    "python.exe", "node.exe", "cmd.exe", "powershell.exe", "Code.exe", 
    "SearchHost.exe", "Taskmgr.exe", "MsMpEng.exe"
]

def log_ips_action(module, message):
    record = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": f"IPS {module}",
        "status": message,
        "is_anomaly": False,
        "is_mitigation": True,
        "confidence": 100
    }
    try:
        with open(ALERTS_FILE, "a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")
    except Exception:
        pass

def is_suspicious_path(proc):
    """
    Evaluates where the program is actually running from.
    Malware usually hides in Temp, AppData, or Downloads.
    """
    try:
        # Get the absolute file path of the executable
        exe_path = proc.info.get('exe')
        if not exe_path:
            return False
            
        exe_path = exe_path.lower()
        
        # TRUSTED ZONES: Ignore heavy applications running from official OS folders
        if "c:\\program files" in exe_path or "c:\\windows" in exe_path:
            return False
            
        # DANGER ZONES: Flag executables running from user-writable temporary spaces
        if "appdata\\local\\temp" in exe_path or "downloads" in exe_path or "appdata\\roaming" in exe_path:
            return True
            
        # If it's not in a trusted zone, treat it with suspicion
        return True
        
    except (psutil.AccessDenied, AttributeError):
        return False

def mitigate_system_threat():
    print("[*] Initiating Smart Process Hunt (CPU + Path Heuristics)...")
    
    procs = []
    # We now fetch 'exe' (file path) alongside pid and name
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
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
            
            # Step 1: Check Whitelist
            if p_name and p_name.lower() not in [w.lower() for w in WHITELIST]:
                
                # Step 2: Measure CPU
                cpu = proc.cpu_percent(interval=None)
                if cpu > 3.0:
                    
                    # Step 3: The New Heuristic Check - Is it in a safe folder?
                    if is_suspicious_path(proc):
                        if cpu > max_cpu:
                            max_cpu = cpu
                            target_proc = proc
                            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    if target_proc:
        try:
            p_name = target_proc.info['name']
            p_pid = target_proc.info['pid']
            p_path = target_proc.info.get('exe', 'Unknown Path')
            
            target_proc.terminate()
            msg = f"Terminated {p_name} (PID {p_pid}) | CPU: {max_cpu}% | Path: {p_path}"
            print(f"\n[🛡️ IPS ACTION] {msg}")
            log_ips_action("Heuristic EDR", msg)
            
        except Exception as e:
            print(f"[!] Could not terminate {target_proc.info['name']}: {e}")
    else:
        print("[*] Hunt complete: No highly-suspicious, high-CPU processes found outside trusted folders.")

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
    print("    🛡️ SMART IPS ENGINE (EDR) ACTIVE")
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
                if alert.get("is_anomaly") and not alert.get("is_mitigation"):
                    source = alert.get("source", "")
                    
                    if source == "System ML":
                        print(f"\n[!] Mitigation Triggered by: {alert.get('status')}")
                        mitigate_system_threat()
                        
                    elif source == "Network ML":
                        print(f"\n[!] Mitigation Triggered by: {alert.get('status')}")
                        mitigate_network_threat()
                        
            except (json.JSONDecodeError, Exception):
                pass

if __name__ == "__main__":
    try:
        start_active_response()
    except KeyboardInterrupt:
        print("\n[*] Smart IPS Engine shut down manually.")