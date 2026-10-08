"""
Sentinel V3 Graph Neural Network (GNN) Module

This module contains two representations of the path prediction model:
1. model.py: The advanced AttackPathGraphSAGE implementation containing the true 
   GraphSAGELayer mathematics (mean aggregation).
2. predictor.py: The operational wrapper PathPredictor which loads a simplified 
   GNNModel (2-layer linear + link head) and handles the Native NumPy fallback 
   if PyTorch is not available in the deployment environment.
"""
