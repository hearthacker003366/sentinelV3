import subprocess
import sys
import os
import time

def kill_port(port):
    """Safely terminate only Sentinel/python processes listening on target port (§2.10)."""
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return

    if os.name == 'nt':
        try:
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=False)
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and "LISTENING" in parts and f":{port_int}" in parts[1]:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) > 4:
                        # Verify process name is python before killing
                        tlist = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                               capture_output=True, text=True, check=False)
                        if "python" in tlist.stdout.lower():
                            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, check=False)
        except Exception:
            pass
    else:
        try:
            res = subprocess.run(["lsof", "-t", f"-i:{port_int}"], capture_output=True, text=True, check=False)
            for pid in res.stdout.strip().split():
                if pid.isdigit() and int(pid) > 1:
                    subprocess.run(["kill", "-9", pid], capture_output=True, check=False)
        except Exception:
            pass

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
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=False)
        if ":8515" in res.stdout and "LISTENING" in res.stdout:
            print(" - Dashboard: ONLINE (Port 8515)")
        else:
            print(" - Dashboard: OFFLINE")
    else:
        res = subprocess.run(["lsof", "-i:8515"], capture_output=True, text=True, check=False)
        if "LISTEN" in res.stdout:
            print(" - Dashboard: ONLINE (Port 8515)")
        else:
            print(" - Dashboard: OFFLINE")

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
