"""
Sentinel V3 Laya System-1 Fast Triage Package
============================================
Fast, non-autoregressive triage gate providing sub-50ms incident classification,
predictive lateral movement path forecasting, and instant Hermes / Honeypot dispatch.
"""

from .laya_triage_engine import LayaTriageEngine, LayaTriageResult

__all__ = ["LayaTriageEngine", "LayaTriageResult"]
