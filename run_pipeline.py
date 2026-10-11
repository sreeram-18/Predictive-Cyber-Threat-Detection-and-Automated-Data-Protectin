import subprocess
import sys
import time
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

PIPELINE_SCRIPTS = [
    "Collectors/network_collector.py",
    "Processing/network_behaviour.py",
    "Processing/network_feature_mapper.py",
    "Model/realtime_detector.py",
    "Collectors/eventlog_collector.py",
    "Collectors/canary_ransomeware_guard.py",
    "Collectors/system_collector.py",
    "Processing/system_behaviour.py",
    "Processing/system_feature_mapper.py",
    "Model/system_detector.py"
]

processes = []

def start_pipeline():
    print("==========================================")
    print("      STARTING FULL AI SIEM PIPELINE      ")
    print("==========================================\n")
    
    try:
        # 1. Boot Python Security Engine
        for script in PIPELINE_SCRIPTS:
            print(f"[*] Launching: {script}")
            process = subprocess.Popen([sys.executable, script])
            processes.append(process)
            time.sleep(1.5) 

        # 2. Boot Node.js Backend API
        print("[*] Launching: Node.js Backend API (Port 4000)")
        backend_dir = os.path.join(PROJECT_ROOT, "backend")
        backend_process = subprocess.Popen("node server.js", shell=True, cwd=backend_dir)
        processes.append(backend_process)
        time.sleep(2)

        # 3. Boot React Frontend
        print("[*] Launching: React Dashboard (Port 3000)")
        # Correctly maps to the nested React app
        frontend_dir = os.path.join(PROJECT_ROOT, "frontend", "siem-dashboard")
        frontend_process = subprocess.Popen("npm start", shell=True, cwd=frontend_dir)
        processes.append(frontend_process)

        print("\n[+] All systems active. Dashboard is opening in your browser...")
        print("[!] Press Ctrl+C to shut down all processes safely.\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[!] Shutdown signal received. Terminating pipeline...")
        for p in processes:
            p.terminate()
        print("[+] Pipeline shut down successfully.")

if __name__ == "__main__":
    start_pipeline()