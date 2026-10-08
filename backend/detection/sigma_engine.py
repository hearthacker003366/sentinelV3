"""
Sentinel Sigma Rule Detection Engine
Evaluates normalized security events against MITRE ATT&CK Sigma rules in real time.
"""

import os
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class SigmaEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[Dict[str, Any]] = []
        if rules_dir is None:
            curr_dir = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(curr_dir, "rules")
        self.load_rules_from_dir(rules_dir)

    def load_rules_from_dir(self, directory: str):
        if not os.path.exists(directory):
            return

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if data and "rules" in data:
                                self.rules.extend(data["rules"])
                            elif data and "id" in data:
                                self.rules.append(data)
                    except Exception as e:
                        print(f"[SigmaEngine] Error loading {filepath}: {e}")

        # IMPORTANT: diagnostics MUST go to stderr — stdout is the JSON-RPC
        # transport for the MCP stdio server; any print() there corrupts the
        # protocol stream (real clients fail to parse the first response).
        import sys as _sys
        _sys.stderr.write(f"[SigmaEngine] Loaded {len(self.rules)} Sigma detection rules.\n")

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a normalized event against all active Sigma rules.
        Returns a list of matched alert objects.
        """
        alerts = []
        for rule in self.rules:
            if self._matches(rule, event):
                alerts.append({
                    "rule_id": rule.get("id"),
                    "title": rule.get("title"),
                    "description": rule.get("description"),
                    "level": rule.get("level", "medium").upper(),
                    "mitre_attack": rule.get("mitre_attack", []),
                    "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "host": event.get("host"),
                    "user": event.get("user"),
                    "event_type": event.get("event_type"),
                    "matched_event": event
                })
        return alerts

    def _matches(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})

        for field_expr, expected_val in selection.items():
            field_name, op = self._parse_field_expr(field_expr)
            actual_val = self._extract_field_value(field_name, event)

            if actual_val is None:
                return False

            if op == "contains":
                actual_str = str(actual_val).lower()
                if isinstance(expected_val, list):
                    if not any(exp.lower() in actual_str for exp in expected_val):
                        return False
                else:
                    if str(expected_val).lower() not in actual_str:
                        return False

            elif op == "in":
                actual_str = str(actual_val).lower()
                if isinstance(expected_val, list):
                    if not any(exp.lower() == actual_str for exp in expected_val):
                        return False
                else:
                    if str(expected_val).lower() != actual_str:
                        return False

            else:  # exact match
                if str(actual_val).lower() != str(expected_val).lower():
                    return False

        return True

    def _parse_field_expr(self, expr: str) -> tuple:
        if "|" in expr:
            parts = expr.split("|", 1)
            return parts[0], parts[1]
        return expr, "exact"

    def _extract_field_value(self, field_name: str, event: Dict[str, Any]) -> Any:
        # Check direct fields
        if field_name in event:
            return event[field_name]

        proc = event.get("process", {})
        if field_name == "command_line":
            return proc.get("command_line")
        if field_name == "process_name":
            return proc.get("name")
        if field_name == "parent_name":
            return proc.get("parent_name")
        if field_name == "target_name":
            return proc.get("target_name")

        net = event.get("network", {})
        if field_name == "dest_port":
            return net.get("dest_port")
        if field_name == "dest_ip":
            return net.get("dest_ip")

        return None
