"""
Sentinel Real Honeypot
======================
A genuine, dependency-free multi-port honeypot listener.

What it REALLY does (no simulation):
  * Binds real TCP ports (SSH-banner pot on 2222, HTTP pot on 8080 by default).
  * Accepts attacker connections, speaks a convincing protocol banner.
  * Captures SSH username/password attempts and full HTTP request lines.
  * Persists every capture into `backend/sentinel.db`:
      - `honeypot_captures` table (full forensic record)
      - `threats` table     (status=TRAPPED, surfaced on dashboards)
  * Registers the source IP in the SOAR blocked list via the caller.

Design notes:
  * Pure stdlib (socketserver). No Docker, no external deps.
  * Binds 127.0.0.1 by default (safe); set SENTINEL_HP_BIND=0.0.0.0 for VM-wide.
  * Every connection handled in its own thread with a hard timeout.
  * Never executes captured input — only records it.
"""

import os
import json
import socket
import socketserver
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

try:
    from backend import _paths
except ImportError:  # direct-script execution
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from backend import _paths

DEFAULT_PORTS = {
    "ssh": int(os.getenv("SENTINEL_HP_SSH_PORT", "2222")),
    "http": int(os.getenv("SENTINEL_HP_HTTP_PORT", "8080")),
}

FAKE_SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
CONNECTION_TIMEOUT = 8.0  # seconds per attacker connection


class HoneypotService:
    """Real TCP honeypot with SQLite persistence and thread-safe lifecycle."""

    def __init__(self, db_path: Optional[str] = None, bind_host: Optional[str] = None,
                 ports: Optional[Dict[str, int]] = None):
        self.db_path = db_path or _paths.db_path()
        self.bind_host = bind_host or os.getenv("SENTINEL_HP_BIND", "127.0.0.1")
        self.ports = ports or DEFAULT_PORTS
        self._servers: List[socketserver.ThreadingTCPServer] = []
        self._threads: List[threading.Thread] = []
        self._running = threading.Event()
        self.captures: List[Dict[str, Any]] = []  # in-memory mirror for dashboards
        self._lock = threading.Lock()
        self._ensure_tables()

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------
    def _ensure_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS honeypot_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    pot_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            # The legacy `threats` table (surfaced by query_threats / dashboards).
            # Created here so a FRESH database is fully self-sufficient —
            # previously this only existed if a V1/V2 script had made it first,
            # which silently broke captures on clean installs.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    type TEXT NOT NULL,
                    details TEXT,
                    status TEXT NOT NULL DEFAULT 'NEW'
                )
            """)

    def _persist_capture(self, source_ip: str, source_port: int, pot_type: str, payload: str):
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.captures.append({
                "timestamp": now_iso, "source_ip": source_ip,
                "source_port": source_port, "pot_type": pot_type, "payload": payload,
            })
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO honeypot_captures (timestamp, source_ip, source_port, pot_type, payload, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (now_iso, source_ip, source_port, pot_type, payload, time.time()),
                )
                # Surface as a trapped threat for dashboards / MCP query_threats
                conn.execute(
                    "INSERT INTO threats (timestamp, ip, type, details, status) VALUES (?,?,?,?,?)",
                    (now_iso, source_ip, f"HONEYPOT_{pot_type.upper()}",
                     payload[:300], "TRAPPED"),
                )
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------
    # Protocol handlers (capture-only — never execute input)
    # ------------------------------------------------------------------
    def _handle_ssh_pot(self, rfile, wfile, source_ip: str, source_port: int):
        wfile.write(FAKE_SSH_BANNER)
        wfile.flush()
        wfile.write(b"login: ")
        wfile.flush()
        rfile_reader = getattr(rfile, "readline", None)
        if not rfile_reader:
            return
        username = (rfile_reader(64) or b"").decode("utf-8", "replace").strip()
        if not username:
            return
        wfile.write(b"Password: ")
        wfile.flush()
        password = (rfile_reader(64) or b"").decode("utf-8", "replace").strip()
        payload = json.dumps({"event": "ssh_auth_attempt", "username": username,
                              "password": password if password else "(none)"})
        self._persist_capture(source_ip, source_port, "ssh", payload)
        wfile.write(b"\r\nPermission denied\r\n\r\n")
        wfile.flush()
        time.sleep(0.3)

    def _handle_http_pot(self, rfile, wfile, source_ip: str, source_port: int):
        request_line = (getattr(rfile, "readline", lambda *a: b"")(256) or b"").decode("utf-8", "replace").strip()
        headers: List[str] = []
        while True:
            line = (getattr(rfile, "readline", lambda *a: b"")(256) or b"").decode("utf-8", "replace").strip()
            if not line:
                break
            headers.append(line)
            if len(headers) > 20:
                break
        payload = json.dumps({"event": "http_request", "request_line": request_line,
                              "headers": headers[:10]})
        self._persist_capture(source_ip, source_port, "http", payload)
        body = b"<html><body><h1>404 Not Found</h1><hr>nginx</body></html>"
        wfile.write(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\n")
        wfile.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
        wfile.write(body)
        wfile.flush()

    # ------------------------------------------------------------------
    # Server plumbing
    # ------------------------------------------------------------------
    def _make_handler(self, pot_type: str):
        service = self

        class PotHandler(socketserver.StreamRequestHandler):
            timeout = CONNECTION_TIMEOUT

            def handle(self):
                source_ip = self.client_address[0]
                source_port = self.client_address[1]
                try:
                    if pot_type == "ssh":
                        service._handle_ssh_pot(self.rfile, self.wfile, source_ip, source_port)
                    elif pot_type == "http":
                        service._handle_http_pot(self.rfile, self.wfile, source_ip, source_port)
                except (ConnectionResetError, socket.timeout, OSError):
                    pass  # attacker hung up — normal

        return PotHandler

    def start(self) -> Dict[str, Any]:
        """Starts all pots. Returns status dict. Idempotent."""
        if self._running.is_set():
            return {"status": "ALREADY_RUNNING", "ports": self.ports, "mode": "REAL"}
        for pot_type, port in self.ports.items():
            try:
                srv = socketserver.ThreadingTCPServer((self.bind_host, port), self._make_handler(pot_type))
                srv.daemon_threads = True
                self._servers.append(srv)
                t = threading.Thread(target=srv.serve_forever, daemon=True,
                                     name=f"sentinel-honeypot-{pot_type}")
                t.start()
                self._threads.append(t)
            except OSError as e:
                return {"status": "ERROR", "error": f"Could not bind {self.bind_host}:{port} ({e})", "mode": "REAL"}
        self._running.set()
        return {"status": "RUNNING", "bind": self.bind_host, "ports": self.ports, "mode": "REAL",
                "message": f"Real honeypot listening on {list(self.ports.values())} — all captures persist to sentinel.db"}

    def stop(self):
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        self._servers.clear()
        self._running.clear()

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    # ------------------------------------------------------------------
    def get_captures(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM honeypot_captures ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return list(reversed(self.captures))[:limit]

    @staticmethod
    def _listening_ports() -> set:
        """Every TCP port in LISTEN state on this host, read from /proc.

        Non-intrusive by design. An earlier revision used
        socket.create_connection() to probe liveness; that WORKS but is not
        side-effect free -- a completed connect() is a real attacker connection
        that the honeypot dutifully records as a capture. Polling the dashboard
        every 2.5s would manufacture hundreds of fake "attacks" from
        127.0.0.1 and corrupt the forensic table it exists to protect.

        Parsing /proc/net/tcp{6} asks the kernel what is bound without touching
        the socket at all.
        """
        found = set()
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path, "r") as fh:
                    next(fh, None)  # header
                    for line in fh:
                        parts = line.split()
                        # parts[1]=local_address hex "IP:PORT", parts[3]=st (0A == LISTEN)
                        if len(parts) > 3 and parts[3].upper() == "0A":
                            try:
                                found.add(int(parts[1].rsplit(":", 1)[1], 16))
                            except (ValueError, IndexError):
                                continue
            except (OSError, StopIteration):
                continue
        return found

    def _port_is_listening(self, port: int) -> bool:
        """True when <port> is in LISTEN state on this host, by any process."""
        try:
            return int(port) in self._listening_ports()
        except (TypeError, ValueError):
            return False

    def _probe_status(self) -> Dict[str, Any]:
        """OS-level truth about the honeypot ports, independent of owner."""
        per_port = {}
        listening = 0
        for name, port in self.ports.items():
            up = self._port_is_listening(port)
            per_port[str(port)] = up
            if up:
                listening += 1

        total = len(self.ports)
        if listening == total:
            state = "ONLINE"
        elif listening:
            state = "DEGRADED"
        else:
            state = "OFFLINE"

        return {
            "running": listening > 0,
            "state": state,
            "listening_ports": [int(p) for p, up in per_port.items() if up],
            "ports_detail": per_port,
            "bind": self.bind_host,
            "ports": self.ports,
            "mode": "REAL",
            "total_captures": len(self.get_captures(limit=10000)),
            "implementation": "pure-python socketserver (no docker, no simulation)",
            "owned_by_this_process": self._running.is_set(),
            "probe_method": "read-only /proc/net/tcp LISTEN scan (no socket touched)",
        }

    def get_status(self) -> Dict[str, Any]:
        """Report honeypot liveness by probing the OS, not local state.

        self.is_running is a process-local threading.Event, so it answered
        "OFFLINE" from the dashboard even while the MCP process held both
        ports. Truth has to come from the OS.
        """
        try:
            return self._probe_status()
        except Exception as e:  # never let a status probe break a tool call
            return {
                "running": self._running.is_set(),
                "state": "UNKNOWN",
                "bind": self.bind_host,
                "ports": self.ports,
                "mode": "REAL",
                "total_captures": 0,
                "error": f"{type(e).__name__}: {e}",
                "implementation": "pure-python socketserver (no docker, no simulation)",
            }
