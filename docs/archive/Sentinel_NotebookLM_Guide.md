# Sentinel V3 + Hermes Agent: Comprehensive Architectural Guide

*This document is formatted as a primary source for Google NotebookLM to generate deep-dive podcasts, FAQs, and study guides about the Sentinel V3 architecture.*

## 1. Project Overview & The "Flawless" Architecture
Sentinel V3 is a next-generation, AI-driven Security Operations Center (SOC). It bridges terminal-level attacker activity with an advanced web dashboard, orchestrated by the Hermes Autonomous LLM Agent. 

**Why Linux?**
We built this inside a Linux environment (like Kali Linux) because Linux provides raw, unrestricted access to the network stack and system logs (`/var/log/auth.log`). Threat actors natively use Linux tools (Nmap, SSH brute-forcers, Metasploit). By running Sentinel on Linux, we intercept the exact same kernel-level logs the attackers generate. 
**Is it flawless?** As of the latest patching (D1 through D11 bug fixes), the environment is mathematically deterministic and flawless. The "Two Data Universes" bug was resolved via a `/api/ingest_threat` webhook, meaning terminal attacks now perfectly sync with the visual web graph.

---

## 2. File & Directory Breakdown

### `/mcp_server` (The Agent's Brain)
*   **`server.py`**: The core Unified Server. It hosts the MCP (Model Context Protocol) endpoints allowing Hermes to call Python tools. It initializes the SQLite database, loads the Sigma rules, and manages the baseline inventory.

### `/backend` (The Engine Room)
*   **`watcher.py`**: A sensory daemon that tails `auth.log` in real-time. It detects SSH brute force, SQL injections, and DDoS, then shoots webhooks to the dashboard.
*   **`gnn/predictor.py`**: The Graph Neural Network (GraphSAGE). It uses mathematical probabilities to predict the attacker's next move (e.g., jumping from `WKSTN-04` to `BACKUP-VAULT-01`).
*   **`graph/graph_manager.py`**: Manages the in-memory NetworkX topology of the enterprise.
*   **`honeypot/listener.py`**: Deploys fake vulnerable ports (like 2222 and 8080) to trap attackers.

### `/dashboard` (The Visual Command Center)
*   **`server.py`**: A lightweight HTTP server that serves the UI and acts as the API router (`/api/state`, `/api/ingest_threat`).
*   **`index.html`**: A 0-dependency Vanilla JS, Cyberpunk-themed UI. It renders the glowing Jarvis toasts and the draggable, zoomable D3-style Threat Graph.

### `/tests` & `/simulator`
*   **`ransomware_simulator.py`**: Emits synthetic logs that simulate Advanced Persistent Threats (APTs) for testing.
*   **`test_sentinel_suite.py`**: Pytest suite ensuring the GNN predictions and Sigma engines never break.

### Root Files
*   **`hermes_master_soul_v3.1.md`**: The System Prompt. This is the literal "Soul" of Hermes. It restricts Hermes from hallucinating and forces it to demand human approval before isolating hosts.
*   **`sentinel.db`**: The SQLite database persisting the `soar_audit_v3`, `threats`, and RL (Reinforcement Learning) scores.

---

## 3. About Hermes & The AI Advantage
**Why Hermes?** Traditional SOCs rely on static IF/THEN rules. Hermes is an Autonomous LLM Agent equipped with the Model Context Protocol (MCP). It doesn't just read alerts; it can dynamically *execute code*, query threat intelligence databases, deploy honeypots, and quarantine machines. 

### How Hermes Knows an Attack Happened
Hermes is not blindly guessing. The flow is:
1. The Attacker runs a script (e.g., an Nmap scan or SSH brute force).
2. The Linux OS logs this to `auth.log`.
3. The `watcher.py` daemon sees it, normalizes it, and sends it to the `SigmaEngine`.
4. The Sigma rule triggers a `CRITICAL ALERT`. 
5. Hermes reads this alert via the `get_threat_graph` and `query_threats` MCP tools, recognizing the exact node (e.g., `WKSTN-04`) that was compromised.

---

## 4. The Human-in-the-Loop (HITL) & Telegram Flow
Hermes is aggressive, but we placed a strict **Human-in-the-Loop (HITL)** guardrail so it cannot accidentally shut down a production server.

### How the User Knows an Attack Happened
When Hermes decides a machine needs isolation, it cannot do it unilaterally. 
1. Hermes calls the `request_host_isolation` tool.
2. The Python backend generates a unique Tier-2 AUTH token (e.g., `AUTH-8A4FBC`).
3. The **TelegramNotifier** reads the `.env` file (loaded securely) and dispatches a live push notification directly to the user's smartphone via Telegram: *"CRITICAL: Hermes requests isolation for WKSTN-04. Token: AUTH-8A4FBC"*.
4. The user reads the Telegram message, opens the Chat interface, and pastes the token back to Hermes.
5. Hermes uses `approve_isolation(token)` to finally sever the attacker's connection.

---

## 5. Active Defense: The Honeypot Trap
If the attacker is moving laterally, Hermes can deploy a honeypot.
1. Hermes analyzes the GNN prediction (e.g., Attacker is targeting `BACKUP-VAULT-01`).
2. Hermes calls `deploy_honeypot()`.
3. The backend spins up `listener.py`, binding fake vulnerable services to ports 2222 (SSH) and 8080 (HTTP) directly in the attacker's path.
4. When the attacker scans or attempts to log in to those fake ports, their raw IP and payload are captured and permanently logged to the `captures` table in `sentinel.db`, completely exposing their identity.

---

## 6. Execution Guide (What Scripts to Run)
To bring the entire environment online, the user only runs:
1. `python dashboard/server.py` (Boots the API, GNN, Sigma Engine, and Web UI on Port 8515).
2. `python backend/watcher.py` (Runs in a separate terminal to watch for live attacks).
3. Open `http://127.0.0.1:8515` in the browser to view the live dashboard.
4. Paste `hermes_master_soul_v3.1.md` into the LLM chat to wake up the Hermes Agent.
