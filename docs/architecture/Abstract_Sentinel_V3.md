# Project Sentinel V3.0: Autonomous Active Defense System
**Project Abstract / Executive Summary**

**Overview:**
Project Sentinel V3.0 is a next-generation, AI-driven Security Operations Center (SOC) orchestrator. Unlike traditional SIEMs that passively alert human analysts, Sentinel utilizes a Large Language Model (LLM) agent connected via the Model Context Protocol (MCP) to autonomously detect, mathematically predict, and proactively isolate cyber threats in real-time.

**Core Architecture & "Honest AI" Implementation:**
1. **PyTorch Graph Neural Network (GNN):** 
   Sentinel maps the enterprise network into a Cyber Knowledge Graph. Upon detecting a compromised node, the AI utilizes a PyTorch GraphSAGE Link Predictor. It calculates structural features (Degree Centrality, PageRank) and uses shortest-path algorithms to mathematically forecast the attacker's lateral movement vector, entirely eliminating hard-coded heuristics.
2. **CyberBattleSim Reinforcement Learning (RL):**
   The system implements a reinforcement learning evaluator that scores the AI's defensive actions. Protecting "Crown Jewel" assets yields positive rewards (+15.0 PTS), while false positives or latency yield severe penalties, ensuring the agent constantly optimizes for enterprise safety.
3. **Autonomous Active Defense (Honeypot):**
   When an unknown threat is detected, Sentinel dynamically deploys a Python-based asyncio honeypot (binding to SSH and HTTP ports). It traps the attacker's payload into a SQLite database, patches the firewall via `iptables`, and isolates the host.
4. **Real-Time Human-in-the-Loop (HITL) Alerting:**
   Through native Telegram API integration, Sentinel instantly alerts the Tier-3 human analyst with the predicted attack path, threat intel score, and requires ephemeral token authorization (SOAR) before executing catastrophic network isolations.

**Conclusion:**
Sentinel V3.0 bridges the gap between theoretical AI models and production-grade cybersecurity, demonstrating a fully autonomous, mathematically sound kill-chain defense against Advanced Persistent Threats (APTs).
