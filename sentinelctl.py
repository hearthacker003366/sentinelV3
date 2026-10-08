import subprocess
import sys
import os
import time

def kill_port(port):
    if os.name == 'nt':
        out = subprocess.run(f"netstat -ano | findstr :{port}", shell=True, capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "LISTENING" in line:
                pid = line.split()[-1]
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
    else:
        subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)

def start():
    print("[*] Checking port 8515 hygiene...")
    kill_port(8515)
    
    print("[*] Starting Sentinel Unified Dashboard Server...")
    server_proc = subprocess.Popen([sys.executable, "dashboard/server.py"])
    
    print("[*] Starting Sentinel Terminal Watcher Daemon...")
    watcher_proc = subprocess.Popen([sys.executable, "backend/watcher.py"])
    
    try:
        while True:
            time.sleep(1)
            if server_proc.poll() is not None or watcher_proc.poll() is not None:
                print("[!] A child process died. Shutting down sentinelctl.")
                break
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel infrastructure...")
    finally:
        server_proc.terminate()
        watcher_proc.terminate()
        server_proc.wait()
        watcher_proc.wait()

def status():
    print("[*] Sentinel Status:")
    if os.name == 'nt':
        out = subprocess.run(f"netstat -ano | findstr :8515", shell=True, capture_output=True, text=True).stdout
        if "LISTENING" in out:
            print(" - Dashboard: ONLINE (Port 8515)")
        else:
            print(" - Dashboard: OFFLINE")
    else:
        print(" - OS not natively supported for status check")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sentinelctl.py start|status")
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    if cmd == "start":
        start()
    elif cmd == "status":
        status()
    else:
        print(f"Unknown command: {cmd}")
