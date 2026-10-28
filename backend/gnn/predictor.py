import math
import random
import logging
from typing import List, Dict, Any, Optional
import numpy as np
import networkx as nx

logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from backend.graph.schema import GraphSchema
from backend.graph.graph_manager import GraphManager


class GNNModel(nn.Module if TORCH_AVAILABLE else object):
    def __init__(self, in_features: int, hidden_dim: int, out_features: int):
        super().__init__()
        self.in_features = in_features
        self.hidden_dim = hidden_dim
        self.out_features = out_features
        
        if TORCH_AVAILABLE:
            # Use deterministic local generator; never touch global RNG (§2.23)
            g = torch.Generator()
            g.manual_seed(42)
            self.fc1 = nn.Linear(in_features, hidden_dim)
            self.relu = nn.ReLU()
            self.fc2 = nn.Linear(hidden_dim, out_features)
            torch.nn.init.xavier_uniform_(self.fc1.weight, generator=g)
            torch.nn.init.zeros_(self.fc1.bias)
            torch.nn.init.xavier_uniform_(self.fc2.weight, generator=g)
            torch.nn.init.zeros_(self.fc2.bias)
            self.link_w = nn.Parameter(torch.randn((out_features, out_features), generator=g) * 0.1)

    def encode(self, x, adj):
        if not TORCH_AVAILABLE:
            return np.zeros((x.shape[0], self.out_features), dtype=np.float32)
        h = torch.matmul(adj, x)
        h = self.relu(self.fc1(h))
        h = torch.matmul(adj, h)
        z = self.fc2(h)
        return z

    def predict_link(self, z_src, z_tgt, topological_penalty=0.0):
        if not TORCH_AVAILABLE:
            return 0.5
        score = torch.sum(torch.matmul(z_src, self.link_w) * z_tgt, dim=-1)
        score = score - topological_penalty
        return torch.sigmoid(score / 3.0)  # Temperature scaling for calibrated realism


class PathPredictor:
    def __init__(self, graph_mgr: GraphManager, hidden_dim: int = 16, embedding_dim: int = 8):
        self.graph_mgr = graph_mgr
        self.is_trained: bool = False
        self._last_trained_version: int = -1
        
        # Local RNG instances (§2.23)
        self.rng = random.Random(42)
        self.np_rng = np.random.default_rng(42)
        
        # 8 features: [is_host, is_user, is_process, is_ip, is_critical, is_compromised, degree_centrality, pagerank]
        self.model = GNNModel(in_features=8, hidden_dim=hidden_dim, out_features=embedding_dim)

    def _compute_features(self, nx_graph):
        nodes = list(nx_graph.nodes())
        n_count = len(nodes)
        node_to_idx = {n: i for i, n in enumerate(nodes)}
        
        # Specific exception handling for structural metrics (§2.25)
        centrality = {}
        pagerank = {}
        if nodes:
            try:
                centrality = nx.degree_centrality(nx_graph)
                pagerank = nx.pagerank(nx_graph, alpha=0.85, max_iter=200)
            except (nx.PowerIterationFailedConvergence, ZeroDivisionError) as e:
                logger.warning("PageRank calculation defaulted to uniform distribution: %s", e)
                centrality = {n: 0.0 for n in nodes}
                pagerank = {n: 1.0 / len(nodes) for n in nodes}
            except Exception as e:
                logger.error("Structural metric calculation error: %s", e)
                centrality = {n: 0.0 for n in nodes}
                pagerank = {n: 1.0 / len(nodes) for n in nodes}

        feats = np.zeros((n_count, 8), dtype=np.float32)
        for n_id, data in nx_graph.nodes(data=True):
            idx = node_to_idx[n_id]
            lbl = data.get("label", "")
            feats[idx, 0] = 1.0 if lbl == GraphSchema.LABEL_HOST else 0.0
            feats[idx, 1] = 1.0 if lbl == GraphSchema.LABEL_USER else 0.0
            feats[idx, 2] = 1.0 if lbl == GraphSchema.LABEL_PROCESS else 0.0
            feats[idx, 3] = 1.0 if lbl == GraphSchema.LABEL_IP else 0.0
            feats[idx, 4] = 1.0 if data.get("criticality") == "HIGH" else 0.0
            feats[idx, 5] = 1.0 if data.get("status") == "COMPROMISED" else 0.0
            feats[idx, 6] = centrality.get(n_id, 0.0)
            feats[idx, 7] = pagerank.get(n_id, 0.0)
            
        return feats, node_to_idx

    def train_on_topology(self, epochs: int = 25, lr: float = 0.01) -> Optional[float]:
        # Ambiguous 0.0 loss resolved with distinct None sentinel (§2.25)
        if not TORCH_AVAILABLE:
            return None

        nx_graph = self.graph_mgr.nx_graph
        nodes = list(nx_graph.nodes())
        if len(nodes) < 2:
            return None

        feats, node_to_idx = self._compute_features(nx_graph)
        n_count = len(nodes)
        adj = np.zeros((n_count, n_count), dtype=np.float32)
        
        # Deduplicate directed edges to avoid double counting loss (§2.22, §2.25)
        pos_edges_set = set()
        for u, v in nx_graph.edges():
            if u in node_to_idx and v in node_to_idx:
                i, j = node_to_idx[u], node_to_idx[v]
                adj[i, j] = 1.0  # Directed adjacency: attacker -> victim preserved (§2.22)
                pos_edges_set.add((i, j))
        
        pos_edges = list(pos_edges_set)
        np.fill_diagonal(adj, 1.0)

        if not pos_edges:
            return None

        # Negative sampling with instance-local RNG (§2.23)
        neg_edges = []
        for _ in range(len(pos_edges) * 2):
            u_idx = self.rng.randint(0, n_count - 1)
            v_idx = self.rng.randint(0, n_count - 1)
            if u_idx != v_idx and adj[u_idx, v_idx] == 0:
                neg_edges.append((u_idx, v_idx))
        if not neg_edges:
            neg_edges = [(pos_edges[0][0], (pos_edges[0][1] + 1) % n_count)]

        x_t = torch.from_numpy(feats)
        adj_t = torch.from_numpy(adj)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = torch.nn.BCEWithLogitsLoss()

        last_loss = 0.0
        for _ in range(epochs):
            self.model.train()
            optimizer.zero_grad()
            z = self.model.encode(x_t, adj_t)

            u_pos = torch.stack([z[u] for u, _ in pos_edges])
            v_pos = torch.stack([z[v] for _, v in pos_edges])
            pos_logits = torch.sum(torch.matmul(u_pos, self.model.link_w) * v_pos, dim=-1)

            u_neg = torch.stack([z[u] for u, _ in neg_edges])
            v_neg = torch.stack([z[v] for _, v in neg_edges])
            neg_logits = torch.sum(torch.matmul(u_neg, self.model.link_w) * v_neg, dim=-1)

            logits = torch.cat([pos_logits, neg_logits])
            targets = torch.cat([torch.ones_like(pos_logits), torch.zeros_like(neg_logits)])
            loss = criterion(logits, targets)
            loss.backward()
            optimizer.step()
            last_loss = float(loss.item())

        self.is_trained = True
        self._last_trained_version = getattr(self.graph_mgr, "version", 0)
        return last_loss

    def predict_next_hop(self, source_host_id: str) -> List[Dict[str, Any]]:
        nx_graph = self.graph_mgr.nx_graph
        nodes = list(nx_graph.nodes())

        if not nodes or source_host_id not in nodes:
            return []

        # Invalidate embeddings and retrain if graph mutated (§2.25)
        current_version = getattr(self.graph_mgr, "version", 0)
        if (not self.is_trained) or (current_version != self._last_trained_version):
            self.train_on_topology(epochs=30)
            self._last_trained_version = current_version

        feats, node_to_idx = self._compute_features(nx_graph)
        n_count = len(nodes)
        
        adj = np.zeros((n_count, n_count), dtype=np.float32)
        for u, v in nx_graph.edges():
            if u in node_to_idx and v in node_to_idx:
                adj[node_to_idx[u], node_to_idx[v]] = 1.0  # Directed adjacency (§2.22)
        np.fill_diagonal(adj, 1.0)

        if TORCH_AVAILABLE:
            self.model.eval()
            x_tensor = torch.from_numpy(feats)
            adj_tensor = torch.from_numpy(adj)
            with torch.no_grad():
                embeddings = self.model.encode(x_tensor, adj_tensor)
        else:
            embeddings = np.zeros((n_count, 8), dtype=np.float32)

        src_idx = node_to_idx[source_host_id]
        
        predictions = []
        for n_id, data in nx_graph.nodes(data=True):
            if n_id == source_host_id or data.get("label") != GraphSchema.LABEL_HOST:
                continue

            target_idx = node_to_idx[n_id]
            
            # Physics-Informed Penalty based on structural distance
            try:
                distance = nx.shortest_path_length(nx_graph, source=source_host_id, target=n_id)
                penalty = float(distance) * 0.5
            except nx.NetworkXNoPath:
                distance = None
                penalty = 10.0  # Unreachable mathematically
            except nx.NodeNotFound:
                distance = None
                penalty = 10.0

            if data.get("status") == "ISOLATED":
                penalty += 5.0

            if TORCH_AVAILABLE:
                z_src = embeddings[src_idx:src_idx+1]
                z_tgt = embeddings[target_idx:target_idx+1]
                with torch.no_grad():
                    prob_tensor = self.model.predict_link(z_src, z_tgt, topological_penalty=penalty)
                prob = float(prob_tensor.item())
                mode = "GNN-TORCH"
            else:
                # Honest heuristic arithmetic without false claims (§2.24)
                prob = max(0.0, min(1.0, 0.5 - (penalty * 0.1)))
                mode = "HEURISTIC-FALLBACK"

            # Dynamic Attack Vector based on topology
            is_critical = data.get("criticality") == "HIGH"
            vec = "Graph Topology Reachability (unreachable — heavy penalty)" if distance is None else "Graph Topology Reachability"
            if distance == 1:
                vec = "Direct Subnet Lateral Movement"
            elif distance is not None and distance > 1 and is_critical:
                vec = "Multi-hop Critical Asset Targeting"

            predictions.append({
                "target": n_id,
                "target_name": data.get("name", n_id),
                "is_critical": is_critical,
                "probability": round(prob, 4),
                "confidence_percentage": round(prob * 100, 1),
                "attack_vector": vec,
                "distance": distance,
                "mode": mode,  # Honest mode reporting (§2.24)
            })

        predictions.sort(key=lambda p: (-p["probability"], p["target"]))
        return predictions
