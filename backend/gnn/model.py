"""
Sentinel GraphSAGE & Physics-Informed GNN Model
Implements inductive neighborhood aggregation for graph node representations
and link prediction to forecast the attacker's next lateral hop.
"""

from typing import Dict, Any, List, Optional
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


if TORCH_AVAILABLE:
    class GraphSAGELayer(nn.Module):
        def __init__(self, in_features: int, out_features: int):
            super().__init__()
            self.linear_self = nn.Linear(in_features, out_features, bias=False)
            self.linear_neigh = nn.Linear(in_features, out_features, bias=True)

        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            # Mean aggregation of neighbors: A_norm * X
            deg = torch.sum(adj, dim=-1, keepdim=True)
            deg_inv = torch.where(deg > 0, 1.0 / deg, torch.zeros_like(deg))
            adj_norm = adj * deg_inv

            neigh_feats = torch.matmul(adj_norm, x)
            h_self = self.linear_self(x)
            h_neigh = self.linear_neigh(neigh_feats)
            return F.relu(h_self + h_neigh)

    class AttackPathGraphSAGE(nn.Module):
        def __init__(self, in_dim: int = 16, hidden_dim: int = 32, out_dim: int = 16):
            super().__init__()
            self.layer1 = GraphSAGELayer(in_dim, hidden_dim)
            self.layer2 = GraphSAGELayer(hidden_dim, out_dim)
            self.link_w = nn.Parameter(torch.randn(out_dim, out_dim))

        def encode(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            h1 = self.layer1(x, adj)
            h2 = self.layer2(h1, adj)
            return F.normalize(h2, p=2, dim=-1)

        def predict_link(self, z_u: torch.Tensor, z_v: torch.Tensor, topological_penalty: float = 0.0) -> torch.Tensor:
            # Score: z_u * W * z_v^T - penalty
            score = torch.matmul(torch.matmul(z_u, self.link_w), z_v.t()) - topological_penalty
            return torch.sigmoid(score)

else:
    class NumPyScalar:
        def __init__(self, val: float):
            self.val = float(val)
        def item(self) -> float:
            return self.val
        def __float__(self) -> float:
            return self.val
        def __repr__(self) -> str:
            return f"NumPyScalar({self.val})"

    # High-performance NumPy fallback implementation
    class AttackPathGraphSAGE:
        def __init__(self, in_dim: int = 16, hidden_dim: int = 32, out_dim: int = 16):
            np.random.seed(42)
            self.w1 = np.random.randn(in_dim, hidden_dim) * 0.1
            self.w2 = np.random.randn(hidden_dim, out_dim) * 0.1
            self.link_w = np.random.randn(out_dim, out_dim) * 0.1

        def encode(self, x: np.ndarray, adj: np.ndarray) -> np.ndarray:
            deg = np.sum(adj, axis=-1, keepdims=True)
            deg_inv = np.where(deg > 0, 1.0 / deg, 0.0)
            adj_norm = adj * deg_inv
            # Layer 1
            neigh1 = np.dot(adj_norm, x)
            h1 = np.maximum(0, np.dot(x + neigh1, self.w1))
            # Layer 2
            neigh2 = np.dot(adj_norm, h1)
            h2 = np.maximum(0, np.dot(h1 + neigh2, self.w2))
            norm = np.linalg.norm(h2, axis=-1, keepdims=True) + 1e-8
            return h2 / norm

        def predict_link(self, z_u: np.ndarray, z_v: np.ndarray, topological_penalty: float = 0.0) -> NumPyScalar:
            score = np.dot(np.dot(z_u, self.link_w), z_v.T if hasattr(z_v, "T") else z_v) - topological_penalty
            val = float(1.0 / (1.0 + np.exp(-score)))
            return NumPyScalar(val)
