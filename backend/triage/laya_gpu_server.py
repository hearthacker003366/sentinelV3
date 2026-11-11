"""Sentinel V3 — Host-Side Laya System-1 GPU Inference Bridge.

Runs on the Windows host (NVIDIA RTX 4050 CUDA GPU) and exposes a local
HTTP endpoint on port 8517 so the Kali Linux VM (`kaliOS Clone` in NAT
mode via http://10.0.2.2:8517) gets real sub-55ms 421M Laya triage
predictions without allocating 1.7 GB of VM CPU RAM.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.triage.laya_triage_engine import LayaTriageEngine  # noqa: E402

ENGINE: LayaTriageEngine | None = None


class LayaGPUHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict[str, Any], code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            loaded = ENGINE is not None and ENGINE.agent is not None
            self._send_json({
                "status": "ok",
                "model_loaded": loaded,
                "checkpoint": ENGINE.checkpoint_dir if ENGINE else None,
            })
            return
        self._send_json({"error": "not found"}, code=404)

    def do_POST(self) -> None:
        if self.path != "/triage":
            self._send_json({"error": "not found"}, code=404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json({"error": "invalid json"}, code=400)
            return

        event_text = str(body.get("event", ""))
        ip = body.get("ip")
        threat_type = str(body.get("threat_type", "GENERIC_ALERT"))
        if ENGINE is None:
            self._send_json({"error": "engine not initialized"}, code=503)
            return

        res = ENGINE.triage_event(event_text, ip=ip, threat_type=threat_type)
        self._send_json({
            "verdict": res.verdict,
            "confidence": res.confidence,
            "is_attack": res.is_attack,
            "severity": res.severity,
            "latency_ms": res.latency_ms,
            "action": res.action,
            "source": res.source,
        })

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


def main() -> None:
    global ENGINE
    parser = argparse.ArgumentParser(description="Sentinel V3 Host Laya GPU Bridge")
    parser.add_argument("--host", default=os.getenv("SENTINEL_LAYA_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SENTINEL_LAYA_PORT", "8517")))
    args = parser.parse_args()

    print("[*] Initializing Laya 421M System-1 model on Windows host...", flush=True)
    ENGINE = LayaTriageEngine(laya_url="")
    loaded = ENGINE.agent is not None
    print(f"[*] Laya model loaded={loaded} | checkpoint={ENGINE.checkpoint_dir}", flush=True)
    print(f"[*] Listening on http://{args.host}:{args.port} (Kali VM NAT URL: http://10.0.2.2:{args.port}/triage)", flush=True)

    srv = ThreadingHTTPServer((args.host, args.port), LayaGPUHandler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Laya GPU bridge.")
        srv.server_close()


if __name__ == "__main__":
    main()
