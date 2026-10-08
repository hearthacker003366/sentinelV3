import time
import os`nimport os
import os
import random
import threading
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "backend", "demo_auth.log")
ATTACKER_IP = os.getenv("ATTACKER_IP", "192.168.1.51")  # [DEMO ONLY] Simulated IP

noise_running = False

def background_noise():
    global noise_running
    noise_running = True
    messages = [
        "BENIGN: kernel: [1234.56] eth0: link up",
        "BENIGN: sshd[801]: Accepted publickey for root from 192.168.1.10",
        "BENIGN: CRON[902]: (root) CMD ( /usr/local/bin/cleanup.sh )",
        "BENIGN: systemd[1]: Started Nginx Web Server.",
        "BENIGN: kernel: [UFW ALLOW] IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.2.2 PROTO=TCP DPT=80"
    ]
    with open(LOG_PATH, "a") as f:
        while noise_running:
            f.write(f"{random.choice(messages)}\n")
            f.flush()
            time.sleep(random.uniform(0.1, 1.0))

def simulate_brute_force():
    print(f"\n[*] Simulating Hydra SSH Brute Force from {ATTACKER_IP}...")
    with open(LOG_PATH, "a") as f:
        for i in range(1, 7):
            f.write(f"Sep 15 21:00:0{i} kali sshd[1234]: Failed password for root from {ATTACKER_IP} port 5432{i} ssh2\n")
            f.flush()
            time.sleep(random.uniform(0.5, 1.5))
    print("[+] SSH Brute Force delivered.")

def simulate_port_scan():
    print(f"\n[*] Simulating Nmap Port Scan from {ATTACKER_IP}...")
    with open(LOG_PATH, "a") as f:
        for i in range(1, 12):
            f.write(f"Sep 15 21:05:{10+i} kali kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC={ATTACKER_IP} DST=10.0.2.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=47831 DF PROTO=TCP SPT=44321 DPT={100+i} WINDOW=65535 RES=0x00 SYN URGP=0\n")
            f.flush()
            time.sleep(random.uniform(0.1, 0.4))
    print("[+] Nmap Port Scan delivered.")

def simulate_priv_escalation():
    print(f"\n[*] Simulating Privilege Escalation (sudo) from {ATTACKER_IP}...")
    with open(LOG_PATH, "a") as f:
        for i in range(1, 5):
            f.write(f"Sep 15 21:10:0{i} kali sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/1 ruser=attacker rhost={ATTACKER_IP}  user=root\n")
            f.flush()
            time.sleep(random.uniform(1.0, 3.0))
    print("[+] Privilege Escalation delivered.")

def simulate_sqli():
    print(f"\n[*] Simulating SQL Injection from {ATTACKER_IP}...")
    with open(LOG_PATH, "a") as f:
        f.write(f"Sep 15 21:15:00 kali nginx: [SQLi] GET /login.php?user=admin'+OR+1=1-- SRC={ATTACKER_IP} HTTP/1.1 403\n")
        f.flush()
    print("[+] SQLi payload delivered.")

def simulate_ddos():
    print(f"\n[*] Simulating Slowloris DDoS from {ATTACKER_IP}...")
    with open(LOG_PATH, "a") as f:
        for i in range(1, 15):
            f.write(f"Sep 15 21:20:{10+i} kali nginx: [Slowloris] Connection timeout from SRC={ATTACKER_IP} DPT=80\n")
            f.flush()
            time.sleep(0.05)
    print("[+] DDoS payload delivered.")

def print_menu():
    print("\n==========================================")
    print(" [SKULL] MASTER ATTACK SIMULATOR CONSOLE [SKULL]")
    print("==========================================")
    status = "ON" if noise_running else "OFF"
    print(f" 0. Toggle Background Noise (Matrix Mode): [{status}]")
    print(" 1. Launch SSH Brute Force")
    print(" 2. Launch Nmap Port Scan")
    print(" 3. Launch Privilege Escalation")
    print(" 4. Launch SQL Injection (Web)")
    print(" 5. Launch Slowloris DDoS (Web)")
    print(" 6. Exit")
    print("==========================================")

if __name__ == "__main__":
    while True:
        print_menu()
        choice = input("Select Attack Vector (0-6): ")
        if choice == '0':
            if noise_running:
                noise_running = False
            else:
                t = threading.Thread(target=background_noise, daemon=True)
                t.start()
        elif choice == '1':
            simulate_brute_force()
        elif choice == '2':
            simulate_port_scan()
        elif choice == '3':
            simulate_priv_escalation()
        elif choice == '4':
            simulate_sqli()
        elif choice == '5':
            simulate_ddos()
        elif choice == '6':
            print("Exiting...")
            noise_running = False
            sys.exit(0)
        else:
            print("Invalid choice.")




