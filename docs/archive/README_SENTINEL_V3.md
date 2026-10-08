# Sentinel V3.0 - Autonomous Active Defense

**Master Documentation & System Architecture**

---

## 1. Project Overview
**Sentinel V3.0** is an AI-driven SIEM and SOAR platform. Hermes (a Large Language Model) acts as an autonomous SOC Analyst connecting via the **Model Context Protocol (MCP)**. 

---

## 2. The "Split Brain" Context (Resolved)
- **The Old Graveyard:** The folder `02_AI_Development/Sentinel_BlueTeam` is completely deprecated.
- **The Unified V3 Core:** **THIS folder** (`kali_clone_vm_shared/Sentinel_BlueTeam`) is the absolute Source of Truth.
- **The Unified MCP Server:** The `mcp_server/server.py` is unified as a persistent stateful daemon with 16 tools.

---

## 3. Core Architecture & Honest AI Verification
This system strictly implements "Honest AI". There is no movie magic. All tools return explicit `mode: REAL` or `mode: SIMULATED` JSON labels.

1. **Graph Neural Network (GNN):** 
   - Uses PyTorch `GraphSAGE` with `nx.shortest_path_length` and structural features.
   - `predict_attack_path` returns real sigmoid mathematical output. No hardcoded caps.
2. **Threat Intelligence (`check_threat_intel`):**
   - Queries AbuseIPDB using real HTTP requests if an API key is present.
   - Falls back to `OFFLINE-HEURISTIC`.
   - Results are physically cached in `sentinel.db` with a 24h TTL.
3. **The Python Honeypot (`deploy_honeypot`):**
   - Uses a pure-Python asyncio multithreaded listener daemon (`backend/honeypot/listener.py`).
   - Binds to ports 2222 and 8080. Captures raw packets and payloads, saving them to SQLite.
4. **Stateful SOAR (`` / `request_host_isolation`):**
   - The MCP server maintains a stateful audit log spanning the episode lifecycle.

---

## 4. Master Script Map
- `mcp_server/server.py`: The unified 12-tool MCP server (Stateful Daemon).
- `backend/sentinel.db`: SQLite database for caching intel and logging honeypot connections.
- `backend/gnn/predictor.py`: The pure PyTorch structural GNN predicting lateral movement.
- `backend/honeypot/listener.py`: The raw packet-trapping asyncio daemon.
- `sentinelctl.py`: The consolidated root-level driver for running attacks, predicting, and approving isolation.
- `sentinel-presentation-dash/`: The Next.js 14 App Router presentation deck.

