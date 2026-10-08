"""
Sentinel Dual-Engine Graph Manager
Provides high-performance graph operations with automatic fallback:
- Native Neo4j (via Bolt protocol) when active
- Zero-config in-memory NetworkX graph when Neo4j is offline
"""

import sys
import threading
from typing import Dict, Any, List, Optional
import networkx as nx

from backend.graph.schema import GraphSchema


class GraphManager:
    def __init__(self, neo4j_uri: Optional[str] = None, neo4j_auth: Optional[tuple] = None):
        self.lock = threading.RLock()
        self.nx_graph = nx.MultiDiGraph()
        self.use_neo4j = False
        self.neo4j_driver = None

        if neo4j_uri:
            try:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=neo4j_auth)
                with self.neo4j_driver.session() as session:
                    session.run("RETURN 1")
                self.use_neo4j = True
                sys.stderr.write(f"[GraphManager] Connected to Neo4j at {neo4j_uri}\n")
            except Exception as e:
                sys.stderr.write(f"[GraphManager] Neo4j unavailable ({e}). Using in-memory NetworkX engine.\n")
                self.use_neo4j = False
        else:
            sys.stderr.write("[GraphManager] Operating in high-performance In-Memory NetworkX mode.\n")

    def add_node(self, node_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self.lock:
            props = properties or {}
            props["label"] = label
            props["id"] = node_id
            self.nx_graph.add_node(node_id, **props)

            if self.use_neo4j:
                try:
                    with self.neo4j_driver.session() as session:
                        session.run(
                            f"MERGE (n:{label} {{id: $id}}) SET n += $props",
                            id=node_id, props=props
                        )
                except Exception:
                    pass

            return {"id": node_id, "label": label, "properties": props}

    def add_edge(self, source: str, target: str, edge_type: str, properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self.lock:
            props = properties or {}
            props["type"] = edge_type
            self.nx_graph.add_edge(source, target, key=edge_type, **props)

            if self.use_neo4j:
                try:
                    with self.neo4j_driver.session() as session:
                        session.run(
                            f"MATCH (a {{id: $source}}), (b {{id: $target}}) "
                            f"MERGE (a)-[r:{edge_type}]->(b) SET r += $props",
                            source=source, target=target, props=props
                        )
                except Exception:
                    pass

            return {"source": source, "target": target, "type": edge_type, "properties": props}

    def ingest_normalized_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        with self.lock:
            mutations = []
            host_raw = event.get("host", "UNKNOWN-HOST")
            host_name = host_raw.get("name", "UNKNOWN-HOST") if isinstance(host_raw, dict) else str(host_raw)
            host_id = GraphSchema.make_host_id(host_name)
            mutations.append(self.add_node(host_id, GraphSchema.LABEL_HOST, {
                "name": host_name,
                "criticality": "HIGH" if "BACKUP" in host_name or "DC" in host_name else "NORMAL"
            }))

            user_raw = event.get("user", "")
            user_name = user_raw.get("name", "") if isinstance(user_raw, dict) else str(user_raw)
            if user_name and user_name != "SYSTEM":
                user_id = GraphSchema.make_user_id(user_name)
                mutations.append(self.add_node(user_id, GraphSchema.LABEL_USER, {"name": user_name}))
                mutations.append(self.add_edge(user_id, host_id, GraphSchema.AUTHENTICATED_TO, {
                    "timestamp": event.get("timestamp")
                }))

            ev_type = event.get("event_type")
            proc = event.get("process", {})

            if ev_type == "PROCESS_CREATION":
                child_name = proc.get("name", "unknown.exe")
                child_pid = proc.get("pid", "0")
                child_id = GraphSchema.make_process_id(host_name, child_pid, child_name)

                mutations.append(self.add_node(child_id, GraphSchema.LABEL_PROCESS, {
                    "name": child_name,
                    "cmd": proc.get("command_line", ""),
                    "pid": child_pid,
                    "host": host_name,
                    "compromised": False
                }))
                mutations.append(self.add_edge(host_id, child_id, "HOSTS", {}))

                parent_name = proc.get("parent_name")
                parent_pid = proc.get("parent_pid")
                if parent_name and parent_pid:
                    parent_id = GraphSchema.make_process_id(host_name, parent_pid, parent_name)
                    self.add_node(parent_id, GraphSchema.LABEL_PROCESS, {
                        "name": parent_name,
                        "pid": parent_pid,
                        "host": host_name
                    })
                    mutations.append(self.add_edge(parent_id, child_id, GraphSchema.PARENT_OF, {
                        "timestamp": event.get("timestamp")
                    }))

            elif ev_type == "NETWORK_CONNECTION":
                net = event.get("network", {})
                dest_ip = net.get("dest_ip")
                dest_port = net.get("dest_port")
                if dest_ip:
                    ip_id = GraphSchema.make_ip_id(dest_ip)
                    mutations.append(self.add_node(ip_id, GraphSchema.LABEL_IP, {
                        "ip": dest_ip,
                        "port": dest_port,
                        "is_internal": dest_ip.startswith("192.168.") or dest_ip.startswith("10.")
                    }))
                    mutations.append(self.add_edge(host_id, ip_id, GraphSchema.NETWORK_CONNECTION, {
                        "protocol": net.get("protocol", "TCP"),
                        "port": dest_port,
                        "timestamp": event.get("timestamp")
                    }))

            elif ev_type == "PROCESS_ACCESS":
                src_name = proc.get("source_name", "")
                target_name = proc.get("target_name", "")
                if src_name and target_name:
                    src_id = GraphSchema.make_process_id(host_name, "active", src_name)
                    tgt_id = GraphSchema.make_process_id(host_name, "system", target_name)
                    self.add_node(src_id, GraphSchema.LABEL_PROCESS, {"name": src_name, "host": host_name})
                    self.add_node(tgt_id, GraphSchema.LABEL_PROCESS, {"name": target_name, "host": host_name})
                    mutations.append(self.add_edge(src_id, tgt_id, GraphSchema.INJECTED_INTO, {
                        "access": proc.get("granted_access", ""),
                        "timestamp": event.get("timestamp")
                    }))

            elif ev_type == "AUTHENTICATION":
                auth = event.get("auth", {})
                if user_id and host_id:
                    mutations.append(self.add_edge(user_id, host_id, GraphSchema.AUTHENTICATED_TO, {
                        "success": auth.get("success", True),
                        "logon_type": auth.get("logon_type", 3),
                        "ip_address": auth.get("ip_address", ""),
                        "timestamp": event.get("timestamp")
                    }))

            elif ev_type == "FILE_CREATION":
                file_info = event.get("file", {})
                target_file = file_info.get("path") or file_info.get("name")
                if target_file:
                    file_id = GraphSchema.make_file_id(host_name, target_file)
                    mutations.append(self.add_node(file_id, GraphSchema.LABEL_FILE, {
                        "name": file_info.get("name", target_file),
                        "path": target_file,
                        "host": host_name
                    }))
                    parent_proc = proc.get("name")
                    if parent_proc:
                        proc_node_id = GraphSchema.make_process_id(host_name, "active", parent_proc)
                        self.add_node(proc_node_id, GraphSchema.LABEL_PROCESS, {"name": parent_proc, "host": host_name})
                        mutations.append(self.add_edge(proc_node_id, file_id, GraphSchema.CREATED_FILE, {
                            "timestamp": event.get("timestamp")
                        }))
                    else:
                        mutations.append(self.add_edge(host_id, file_id, GraphSchema.CREATED_FILE, {
                            "timestamp": event.get("timestamp")
                        }))

            return mutations

    def mark_node_compromised(self, node_id: str, severity: str = "CRITICAL", reason: str = ""):
        with self.lock:
            if node_id in self.nx_graph.nodes:
                self.nx_graph.nodes[node_id]["status"] = "COMPROMISED"
                self.nx_graph.nodes[node_id]["severity"] = severity
                self.nx_graph.nodes[node_id]["reason"] = reason

    def mark_predicted_path(self, source_id: str, target_id: str, probability: float):
        with self.lock:
            self.add_edge(source_id, target_id, GraphSchema.PREDICTED_ATTACK_PATH, {
                "probability": probability,
                "status": "PREDICTED",
                "label": f"PREDICTED HOP ({int(probability * 100)}%)"
            })
            if target_id in self.nx_graph.nodes:
                self.nx_graph.nodes[target_id]["status"] = "PREDICTED_TARGET"
                self.nx_graph.nodes[target_id]["risk_score"] = probability

    def get_cytoscape_elements(self) -> List[Dict[str, Any]]:
        with self.lock:
            elements = []
            for n_id, data in self.nx_graph.nodes(data=True):
                elements.append({
                    "data": {
                        "id": n_id,
                        "label": data.get("name", n_id.split(":")[-1]),
                        "type": data.get("label", "Generic"),
                        "status": data.get("status", "HEALTHY"),
                        "severity": data.get("severity", "LOW"),
                        "criticality": data.get("criticality", "NORMAL"),
                        **data
                    }
                })

            edge_idx = 0
            for u, v, k, data in self.nx_graph.edges(keys=True, data=True):
                elements.append({
                    "data": {
                        "id": f"e_{edge_idx}",
                        "source": u,
                        "target": v,
                        "type": k,
                        "status": data.get("status", "NORMAL"),
                        "probability": data.get("probability", None),
                        "label": data.get("label", k)
                    }
                })
                edge_idx += 1

            return elements

    def clear(self):
        with self.lock:
            self.nx_graph.clear()
            if self.use_neo4j and self.neo4j_driver:
                try:
                    with self.neo4j_driver.session() as s:
                        s.run("MATCH (n) DETACH DELETE n")
                except Exception:
                    pass
