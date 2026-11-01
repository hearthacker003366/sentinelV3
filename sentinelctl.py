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

def clean_session():
    """Reset ephemeral session telemetry on fresh boot while preserving RL and audit state."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    mem_path = os.path.join(base_dir, "backend", "mem_state.json")
    if os.path.exists(mem_path):
        try:
            os.remove(mem_path)
            print("[*] Cleaned stale mem_state.json.")
        except Exception:
            pass
    log_path = os.path.join(base_dir, "backend", "demo_auth.log")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.truncate(0)
        print("[*] Reset demo_auth.log to clean 0-byte stream.")
    except Exception:
        pass
    db_path = os.path.join(base_dir, "backend", "sentinel.db")
    if os.path.exists(db_path):
        try:
            import sqlite3
            with sqlite3.connect(db_path, timeout=10.0) as conn:
                conn.execute("DELETE FROM threats;")
                conn.execute("DELETE FROM laya_triage_log;")
                conn.commit()
            print("[*] Cleared previous threat session tables (RL score & SOAR audit preserved).")
        except Exception as e:
            print(f"[!] Warning cleaning db session: {e}")

def start():
    print("[*] Checking port 8515 hygiene...")
    kill_port(8515)
    
    # Clean stale session telemetry so dashboard starts fresh
    clean_session()
    mem_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "mem_state.json")
    if os.path.exists(mem_path):
        try:
            os.remove(mem_path)
            print("[*] Cleaned stale mem_state.json.")
        except Exception:
            pass

    print("[*] Starting Sentinel Unified Dashboard Server...")
    print("    -> Access on VM & Host at: http://127.0.0.1:8515 or http://localhost:8515")
    server_proc = subprocess.Popen([sys.executable, "dashboard/server.py", "--host", "0.0.0.0", "--port", "8515"])
    
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
        print("Usage: sentinelctl.py start|status|reset")
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    if cmd == "start":
        start()
    elif cmd == "status":
        status()
    elif cmd == "reset":
        clean_session()
        status()
    else:
        print(f"Unknown command: {cmd}")
