import time
import sqlite3
import os
import datetime
import re
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentinel.db")
LOG_PATH = os.path.join(BASE_DIR, "demo_auth.log")

# ANSI Color Codes
RED = '\033[91m'
RESET = '\033[0m'
CYAN = '\033[96m'
DIM = '\033[90m'

def init_demo_log():
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, "w").close()

def report_threat(ip, threat_type, details):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO threats (ip, type, details, status, timestamp) VALUES (?, ?, ?, 'NEW', ?)", (ip, threat_type, details, datetime.datetime.utcnow().isoformat() + "Z"))
    conn.commit()
    conn.close()
    
    # Bridge D7: Send to web API so it appears in the visual graph
    try:
        import urllib.request, json
        data = json.dumps({"ip": ip, "type": threat_type, "details": details, "timestamp": datetime.datetime.utcnow().isoformat() + "Z"}).encode('utf-8')
        req = urllib.request.Request("http://127.0.0.1:8515/api/ingest_threat", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        pass
    
    print(f"\n{RED}[!!!] CRITICAL THREAT DETECTED [!!!]{RESET}")
    print(f"{RED}Type: {threat_type} | Source IP: {ip}{RESET}")
    print(f"{RED}Action: Written to database. Waiting for Hermes Active Defense...{RESET}\n")

def tail_log():
    init_demo_log()
    failed_logins = defaultdict(int)
    sudo_failures = defaultdict(int)
    port_scans = defaultdict(int)
    
    with open(LOG_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            # Print benign logs in Matrix Gray, malicious logs get caught below
            if "BENIGN" in line:
                print(f"{DIM}[STREAM] {line.strip()}{RESET}")
            else:
                print(f"{CYAN}[ALERT LOG] {line.strip()}{RESET}")
            
            # 1. Detect SSH Brute Force
            ssh_match = re.search(r'Failed password for .* from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if ssh_match:
                ip = ssh_match.group(1)
                failed_logins[ip] += 1
                if failed_logins[ip] == 5:
                    report_threat(ip, "BRUTE_FORCE_SSH", "5+ failed SSH login attempts detected.")
                    failed_logins[ip] = 0
            
            # 2. Detect Port Scanning
            scan_match = re.search(r'UFW BLOCK.*SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if scan_match:
                ip = scan_match.group(1)
                port_scans[ip] += 1
                if port_scans[ip] == 10:
                    report_threat(ip, "PORT_SCAN_NMAP", "Aggressive network port scanning detected.")
                    port_scans[ip] = 0
                    
            # 3. Detect Privilege Escalation
            sudo_match = re.search(r'sudo:.*authentication failure.*rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if sudo_match:
                ip = sudo_match.group(1)
                sudo_failures[ip] += 1
                if sudo_failures[ip] == 3:
                    report_threat(ip, "PRIVILEGE_ESCALATION", "Multiple failed 'sudo' root escalation attempts.")
                    sudo_failures[ip] = 0

            # 4. Detect SQL Injection
            sqli_match = re.search(r'\[SQLi\].*SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if sqli_match:
                ip = sqli_match.group(1)
                report_threat(ip, "SQL_INJECTION", "Malicious SQL payload detected in HTTP request.")

            # 5. Detect Slowloris DDoS
            ddos_match = re.search(r'\[Slowloris\].*SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if ddos_match:
                ip = ddos_match.group(1)
                report_threat(ip, "DDOS_SLOWLORIS", "Connection exhaustion attack detected on port 80.")

if __name__ == "__main__":
    print("=========================================================")
    print(" [SHIELD] SENTINEL 2.0 SENSORY DAEMON (LOG WATCHER) ONLINE [SHIELD]")
    print("=========================================================")
    tail_log()




