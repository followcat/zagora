"""Zagora registry server — lightweight HTTP JSON API for session metadata."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


def _data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(xdg) / "zagora"


def _data_path() -> Path:
    return _data_dir() / "sessions.json"


class SessionStore:
    """Thread-safe in-memory session store with JSON file persistence."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _data_path()
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._load()

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._sessions = data
        except (FileNotFoundError, json.JSONDecodeError):
            self._sessions = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._sessions, indent=2, default=str), encoding="utf-8")
        tmp.replace(self._path)

    # -- public API -----------------------------------------------------------

    def list(self, host: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            out = list(self._sessions.values())
        if host:
            out = [s for s in out if s.get("host") == host]
        return out

    def get(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            return self._sessions.get(name)

    def register(self, name: str, host: str, status: str = "running") -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            existing = self._sessions.get(name)
            if existing:
                existing["host"] = host
                existing["status"] = status
                existing["last_seen"] = now
            else:
                self._sessions[name] = {
                    "name": name,
                    "host": host,
                    "status": status,
                    "created_at": now,
                    "last_seen": now,
                }
            self._save()
            return dict(self._sessions[name])

    def remove(self, name: str) -> bool:
        with self._lock:
            if name in self._sessions:
                del self._sessions[name]
                self._save()
                return True
            return False


def _make_handler(store: SessionStore, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: N802
            # quiet logging: single line
            pass

        def _check_token(self) -> bool:
            if not token:
                return True
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {token}":
                return True
            self._json_response(401, {"error": "unauthorized"})
            return False

        def _json_response(self, code: int, body: Any) -> None:
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> Any:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length))

        # -- routes -----------------------------------------------------------

        def do_GET(self):  # noqa: N802
            if not self._check_token():
                return
            if self.path == "/sessions" or self.path.startswith("/sessions?"):
                # parse ?host=xxx
                host = None
                if "?" in self.path:
                    qs = self.path.split("?", 1)[1]
                    for part in qs.split("&"):
                        if part.startswith("host="):
                            host = part[5:]
                sessions = store.list(host=host)
                self._json_response(200, sessions)
            elif self.path.startswith("/sessions/"):
                name = self.path.split("/sessions/", 1)[1]
                s = store.get(name)
                if s:
                    self._json_response(200, s)
                else:
                    self._json_response(404, {"error": "not found"})
            elif self.path == "/health":
                self._json_response(200, {"status": "ok"})
            else:
                self._json_response(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._check_token():
                return
            if self.path == "/sessions":
                body = self._read_json()
                name = body.get("name")
                host = body.get("host")
                if not name or not host:
                    self._json_response(400, {"error": "name and host required"})
                    return
                status = body.get("status", "running")
                s = store.register(name, host, status)
                self._json_response(200, s)
            else:
                self._json_response(404, {"error": "not found"})

        def do_DELETE(self):  # noqa: N802
            if not self._check_token():
                return
            if self.path.startswith("/sessions/"):
                name = self.path.split("/sessions/", 1)[1]
                if store.remove(name):
                    self._json_response(200, {"deleted": name})
                else:
                    self._json_response(404, {"error": "not found"})
            else:
                self._json_response(404, {"error": "not found"})

    return Handler


def run_server(port: int = 9876, token: str | None = None, bind: str = "0.0.0.0") -> None:
    store = SessionStore()
    handler = _make_handler(store, token)
    server = HTTPServer((bind, port), handler)
    print(f"zagora server listening on {bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()
