# 🛡️ Project Sentinel: Master Architecture, Intent & DeepSeek Handover Dossier

> **To DeepSeek / Any Collaborating AI Agent**:
> Read this document to understand the exact motivation, technical architecture, and defense-interception mechanisms of **Project Sentinel**.

---

## 🧭 1. Executive Summary & Why This Project Exists

### The Core Problem
In enterprise cybersecurity, traditional Blue Team defenses (SIEMs, basic EDRs) are purely **reactive**:
1. They generate thousands of disconnected alerts every day (alert fatigue).
2. They typically trigger **only after** an attacker has already executed destructive actions (e.g., after shadow copies are deleted or encryption has begun).
3. System administrators and Tier-1 SOC analysts struggle to correlate multi-hop lateral movement across disparate logs until it is too late.

### The Question We Answered
Our project guide and team lead posed the foundational question:
> *"How does the AI know that an attacker is trying to break in, rather than a normal system administrator, and how can it stop the intrusion before critical assets are compromised?"*

### The Solution: Project Sentinel
**Project Sentinel** is an **Autonomous Tier-3 Blue Team Threat Hunting & Attack-Path Prediction Platform**. 
Instead of looking at logs in isolation, Sentinel maps streaming telemetry into a **Cyber Knowledge Graph**, uses a **Graph Neural Network (GraphSAGE)** to forecast the attacker's next lateral hop before they reach it, and orchestrates containment via an autonomous **Hermes Desktop SOC Lead Bot** with **Reinforcement Learning** and **Two-Tier SOAR**.

---

## ⚔️ 2. "Will It Attack or Not?" — Red Team vs. Blue Team Duality

**Crucial Clarification**:
- **Sentinel is strictly a BLUE TEAM (Defensive) System.** It does NOT launch attacks on real networks or hack into external computers.
- **Safety Invariant**: All attack activities are sandboxed inside a digital-twin synthetic telemetry generator (`simulator/ransomware_simulator.py`). No real destructive commands touch any production machines or adapters.

### Then How Does the Attack Happen, and How Does Sentinel Stop It?
1. **The Attacker (Simulated APT / Ransomware Campaign)**:
   The built-in simulator models a real-world enterprise ransomware outbreak in 5 realistic stages:
   - *Stage 1*: Spearphishing dropper on `HOST:WKSTN-04` connecting to external C2 (`185.220.101.49`).
   - *Stage 2*: Defense evasion (`vssadmin delete shadows` / MITRE T1490) to destroy disaster recovery.
   - *Stage 3*: Internal reconnaissance (probing SMB shares on port 445 toward file servers).
   - *Stage 4*: Target acquisition (preparing lateral movement to encrypt the enterprise backup vault).
   - *Stage 5*: Data encryption / destructive lateral breach attempt.

2. **How Sentinel Stops the Attack (Active Interception)**:
   Sentinel intercepts the attacker **step-by-step as the attack unfolds**:
   - **Stage 1**: Drops the external C2 IP at the perimeter (`BLOCK_IP`). Keeps the workstation active to avoid business stoppage.
   - **Stage 2**: Sigma rule engine detects `vssadmin delete shadows` (T1490) and raises a `CRITICAL` alert. Hermes's `ThreatIntel-Subagent` correlates MITRE tactics.
   - **Stage 3**: Maps the lateral network telemetry into the Cyber Knowledge Graph topology.
   - **Stage 4 (The Climax)**: PyTorch GraphSAGE Link Predictor forecasts that the attacker will target `BACKUP-VAULT-01` with **>90% probability**. Hermes generates a Tier-2 Host Isolation Authorization Token (`AUTH-XXXXXX`) and dispatches a Telegram alert.
   - **Stage 5**: The human operator confirms `AUTH-XXXXXX` $\to$ Sentinel severs `HOST:WKSTN-04` from the network $\to$ `BACKUP-VAULT-01` is **100% saved** before encryption touches it $\to$ awards **+15.0 PTS** Reinforcement Learning score!

---

## 🧠 3. The Role of the Hermes Autonomous SOC Lead Bot

Hermes is **NOT a simple Python script**; it is an **Autonomous Tier-3 SOC Commander** running in continuous monitoring mode (via Hermes Desktop or API) connected to Sentinel through the **Model Context Protocol (MCP)**.

### Hermes's Cognitive Architecture:
1. **Cognitive Hierarchy & Sub-Bots**:
   - 🔍 `ForensicBot`: Reconstructs parent-child process lineages (`invoice.pdf.exe -> powershell.exe -> vssadmin.exe`) and audits memory injection (LSASS).
   - 🌐 `ThreatIntelBot`: Maps raw commands to canonical MITRE ATT&CK techniques (`T1059.001`, `T1490`, `T1003.001`, `T1021.002`).
   - 🛡️ `ContainmentBot`: Evaluates network reachability and formulates Two-Tier SOAR playbooks.
2. **Self-Improving Persistent Memory (`backend/reasoning/memory_ledger.json`)**:
   - When an analyst flags an administrative tool (e.g., `backup_daemon.exe`) as benign, Hermes records it in permanent memory and automatically suppresses future alerts on that pattern.
3. **Reinforcement Learning (CyberBattleSim MDP)**:
   - Evaluates defense reward at every containment action:
     - `+10.0 PTS`: Crown Jewel Asset protected before encryption.
     - `+5.0 PTS`: Early link forecast (<2.5s latency).
     - `-15.0 PTS`: Premature false containment / reward hacking.
     - `-10.0 PTS`: False positive interruption of legitimate admin processes.
     - `-50.0 PTS`: Catastrophic breach of Crown Jewels.
4. **Human-in-the-Loop (HITL) Guardrail**:
   - Hermes CANNOT unilaterally quarantine workstations at Stage 1. Tier-2 containment requires an ephemeral authorization token (`AUTH-XXXXXX`) with a 15-minute TTL approved by the human operator.

---

## 🗂️ 4. Complete Codebase Map & Module Directory

```
Sentinel_BlueTeam/
│
├── backend/
│   ├── ingestion/
│   │   └── log_normalizer.py       # Normalizes Sysmon 1/3/10/11 & Win 4624/4625 to OCSF schema
│   │
│   ├── graph/
│   │   ├── schema.py               # Graph node/edge definitions (Host, User, Process, IP, File)
│   │   └── graph_manager.py        # Dual graph engine (NetworkX + Neo4j fallback) with RLock
│   │
│   ├── detection/
│   │   ├── sigma_engine.py         # Sigma rule evaluator with selection & modifier logic
│   │   └── rules/
│   │       └── ransomware_rules.yaml # MITRE rules (T1490, T1059.001, T1003.001, T1021.002)
│   │
│   ├── gnn/
│   │   ├── model.py                # PyTorch GraphSAGE model + high-performance NumPy fallback
│   │   └── predictor.py            # Link prediction head trained with Adam + BCE loss on topology
│   │
│   ├── containment/
│   │   ├── soar_engine.py          # Two-Tier SOAR (Tier-1 IP block, Tier-2 token-gated quarantine)
│   │   └── telegram_notifier.py    # Real-time incident & containment alerts via Telegram Bot
│   │
│   ├── reasoning/
│   │   ├── hermes_soc_lead.py      # Tier-3 SOC Lead, sub-agents, interactive chat, memory learning
│   │   └── memory_ledger.json      # Permanent persistent memory storage
│   │
│   └── rl/
│       └── rl_evaluator.py         # CyberBattleSim-inspired RL reward scoreboard & policy tracker
│
├── frontend/
│   ├── index.html                  # Cyber SOC Dark-Mode Command Center
│   ├── style.css                   # Glassmorphic cyber defense styling
│   ├── app.js                      # WebSocket, Cytoscape graph renderer, chat, and SOAR cards
│   └── cytoscape.min.js            # 100% locally bundled offline graph library (365 KB)
│
├── simulator/
│   └── ransomware_simulator.py     # 5-Stage APT enterprise ransomware synthetic log generator
│
├── mcp_server/
│   └── server.py                   # Spec-compliant MCP server exposing tools over stdio JSON-RPC
│
├── tests/
│   └── test_sentinel_suite.py      # Comprehensive 10-point unit & integration verification test suite
│
├── server.py                       # FastAPI & WebSocket master server on port 8000
└── run_sentinel.py                 # Single-click launcher with port cleanup and browser auto-launch
```

---

## 🛠️ 5. Recent Critical Bug Fixes (Addressed from Audit)

If reviewing previous commits, note that these 10 fixes have been completely implemented and verified:
1. **NumPy GNN Fallback**: Added `NumPyScalar` wrapper to prevent `AttributeError: no attribute 'item'`.
2. **GNN Training**: Added `train_on_topology` in `predictor.py` with `Adam` optimizer and `BCEWithLogitsLoss`.
3. **Chat Precedence**: Fixed boolean operator grouping in `hermes_soc_lead.py:chat_with_analyst`.
4. **SOAR Token TTL**: Implemented 15-minute token expiry in `soar_engine.py` to prevent replay attacks.
5. **Memory Deduplication**: Prevented duplicate false positive entries and cleaned `memory_ledger.json`.
6. **MITRE Tag Formatting**: Normalized YAML tags to canonical technique IDs (`T1490`, etc.).
7. **Graph Ingestion**: Added dedicated handlers for `AUTHENTICATION` and `FILE_CREATION` events.
8. **Stage Validation**: Enforced `1 <= stage_num <= 5` returning HTTP 400 on invalid input.
9. **MCP Compliance**: Added `initialize` handshake (`protocolVersion: "2024-11-05"`) and JSON-RPC 2.0 error codes.
10. **Frontend Hardening**: Added `escapeHtml` against XSS and prioritized WebSocket over REST fetch to eliminate double-render flicker.

---

## 🚀 6. How to Run and Verify Everything

### 1. Run Automated Test Suite (10/10 Passing):
```powershell
python -m pytest tests/test_sentinel_suite.py
```

### 2. Launch the Master SOC Command Center:
```powershell
python run_sentinel.py
```
- Dashboard runs at **`http://localhost:8000`**.
- WebSockets deliver live Cytoscape graph updates.
- Interactive Hermes Chat available on the right panel.

### 3. Use via MCP in Hermes Desktop / Antigravity:
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "python",
      "args": ["C:/Users/B.prabhudas/Desktop/02_AI_Development/Sentinel_BlueTeam/mcp_server/server.py"],
      "env": {"PYTHONPATH": "C:/Users/B.prabhudas/Desktop/02_AI_Development/Sentinel_BlueTeam"}
    }
  }
}
```

---

## 🎯 7. Suggested Next Directions for DeepSeek

When DeepSeek takes over, here are the most valuable high-impact enhancements it can focus on:
1. **Expand Sigma Rules**: Add new rules in `ransomware_rules.yaml` for DLL Side-Loading (T1574) and Cobalt Strike named pipes (T1055).
2. **Multi-Host Simulator Scenarios**: Add a second APT scenario in `ransomware_simulator.py` (e.g. Akira or LockBit 3.0).
3. **Deep Q-Network (DQN) Policy Head**: Expand `rl_evaluator.py` from a reward ledger into a small active PyTorch DQN policy network that selects defensive actions based on the graph state vector.
