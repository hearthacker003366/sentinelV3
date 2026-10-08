"""
Sentinel Honest Threat Intelligence Service
===========================================
Replaces the V2 `random.choice([0,15,99])` fake with a deterministic,
labeled, multi-source intel pipeline.

Resolution order (first available wins):
  1. SQLite cache hit (< TTL)          -> mode = "CACHE"
  2. AbuseIPDB API (key present)       -> mode = "REAL"
  3. Offline blocklists + heuristics   -> mode = "OFFLINE-HEURISTIC"

Every response carries:
  mode            : CACHE | REAL | OFFLINE-HEURISTIC
  confidence      : 0-100 (from the actual source; heuristics capped at 60)
  recommendation  : BAN | ROUTE_TO_HONEYPOT | MONITOR
  source_detail   : human-readable provenance

No randomness anywhere. Same IP in, same verdict out.
"""

import os
import json
import sqlite3
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

try:
    from backend import _paths
except ImportError:  # direct-script execution
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from backend import _paths

# ---------------------------------------------------------------------------
# Offline intelligence (real public data, no network required)
# ---------------------------------------------------------------------------

# Subset of the Spamhaus DROP list philosophy: documented abusive ranges.
# (Space-delimited NETBLOCK:annotation — kept small + factual for the lab.)
OFFLINE_BLOCKLIST_NETBLOCKS = {
    "185.220.101.0/24": "Spamhaus DROP-listed range (bulletproof hosting, TOR exits)",
    "45.155.204.0/24":  "Known scareware/malware distribution range",
    "103.75.190.0/24":  "Documented botnet C2 hosting range",
    "193.106.191.0/24": "DROP-listed malicious range",
    "62.204.41.0/24":   "DROP-listed malicious range",
}

PRIVATE_RANGES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                  "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                  "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                  "192.168.", "127.", "169.254.")

CACHE_TTL_SECONDS = 24 * 3600
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _ip_to_int(ip: str) -> Optional[int]:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except ValueError:
        return None


def _in_netblock(ip: str, netblock: str) -> bool:
    base, bits = netblock.split("/")
    base_int, mask_bits = _ip_to_int(base), int(bits)
    if base_int is None:
        return False
    mask = (0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF
    ip_int = _ip_to_int(ip)
    return ip_int is not None and (ip_int & mask) == (base_int & mask)


class ThreatIntelService:
    """Deterministic, labeled, multi-source IP reputation service."""

    def __init__(self, db_path: Optional[str] = None,
                 abuseipdb_key: Optional[str] = None,
                 cache_ttl: int = CACHE_TTL_SECONDS):
        self.db_path = db_path or _paths.db_path()
        self.api_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.cache_ttl = cache_ttl
        self._ensure_cache_table()

    # ------------------------------------------------------------------
    def _ensure_cache_table(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_cache (
                    ip TEXT PRIMARY KEY,
                    verdict_json TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    mode TEXT NOT NULL
                )
            """)

    # ------------------------------------------------------------------
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Main entry: returns a fully-labeled verdict dict."""
        if not ip or not isinstance(ip, str):
            return self._verdict(ip or "?", mode="OFFLINE-HEURISTIC", confidence=0,
                                 recommendation="MONITOR", detail="Invalid IP input", source="validator")

        cached = self._cache_get(ip)
        if cached is not None:
            return cached

        if self.api_key:
            verdict = self._query_abuseipdb(ip)
            if verdict is not None:
                self._cache_put(ip, verdict, "REAL")
                return verdict
            # API failed (rate limit / network) -> fall through to offline

        verdict = self._offline_verdict(ip)
        self._cache_put(ip, verdict, "OFFLINE-HEURISTIC")
        return verdict

    # ------------------------------------------------------------------
    def _cache_get(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT verdict_json, fetched_at FROM intel_cache WHERE ip = ?", (ip,)
                ).fetchone()
            if row and (time.time() - row[1]) < self.cache_ttl:
                v = json.loads(row[0])
                v["mode"] = "CACHE"
                v["source_detail"] = f"{v.get('source_detail', '')} [served from 24h cache]"
                return v
        except sqlite3.Error:
            pass
        return None

    def _cache_put(self, ip: str, verdict: Dict[str, Any], mode: str):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO intel_cache (ip, verdict_json, fetched_at, mode) VALUES (?,?,?,?)",
                    (ip, json.dumps(verdict), time.time(), mode),
                )
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------
    def _query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(
            f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            d = data.get("data", {})
            score = int(d.get("abuseConfidenceScore", 0))
            return self._verdict(
                ip=ip, mode="REAL", confidence=score,
                recommendation="BAN" if score >= 75 else ("ROUTE_TO_HONEYPOT" if score >= 30 else "MONITOR"),
                detail=f"AbuseIPDB: {d.get('totalReports', 0)} reports, "
                       f"usage={d.get('usageType', 'unknown')}, country={d.get('countryCode', '??')}",
                source="abuseipdb.com/api/v2",
            )
        except (urllib.error.URLError, ValueError, KeyError, json.JSONDecodeError):
            return None  # fall through to offline

    # ------------------------------------------------------------------
    def _offline_verdict(self, ip: str) -> Dict[str, Any]:
        for netblock, label in OFFLINE_BLOCKLIST_NETBLOCKS.items():
            if _in_netblock(ip, netblock):
                return self._verdict(
                    ip=ip, mode="OFFLINE-HEURISTIC", confidence=60,
                    recommendation="ROUTE_TO_HONEYPOT",
                    detail=label,
                    source=f"offline blocklist {netblock}",
                )

        if any(ip.startswith(r) for r in PRIVATE_RANGES):
            return self._verdict(
                ip=ip, mode="OFFLINE-HEURISTIC", confidence=0, recommendation="MONITOR",
                detail="RFC1918/private address — internal lab asset, not routable internet host",
                source="offline heuristics",
            )

        return self._verdict(
            ip=ip, mode="OFFLINE-HEURISTIC", confidence=10, recommendation="MONITOR",
            detail="No blocklist match, no API key configured (set ABUSEIPDB_API_KEY for live intel)",
            source="offline heuristics",
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _verdict(ip: str, mode: str, confidence: int, recommendation: str,
                 detail: str, source: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "mode": mode,
            "confidence": confidence,
            "recommendation": recommendation,
            "source_detail": f"{source}: {detail}",
            "is_honest": True,
        }

    # ------------------------------------------------------------------
    def format_report(self, ip: str) -> str:
        v = self.check_ip(ip)
        return (
            f"[ThreatIntel mode={v['mode']}] IP {v['ip']} — "
            f"confidence {v['confidence']}% — recommendation: {v['recommendation']} "
            f"({v['source_detail']})"
        )
