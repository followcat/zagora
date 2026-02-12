"""Zagora registry server — lightweight HTTP JSON API for session metadata."""
from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


def _data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(xdg) / "zagora"


def _data_path() -> Path:
    return _data_dir() / "sessions.json"


def _history_path() -> Path:
    return _data_dir() / "history.json"


def _split_host_port(target: str, default_port: int = 22) -> tuple[str, int]:
    s = (target or "").strip()
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("[") and "]" in s:
        idx = s.find("]")
        host = s[1:idx]
        rest = s[idx + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if s.count(":") == 1:
        host, port_s = s.rsplit(":", 1)
        if port_s.isdigit():
            return host, int(port_s)
    return s, default_port


def _probe_host(host: str, timeout: float = 2.0) -> bool:
    target, port = _split_host_port(host, default_port=22)
    if not target:
        return False
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


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
                prev_host = existing.get("host")
                existing["host"] = host
                existing["status"] = status
                existing["last_seen"] = now
                existing.setdefault("host_reachable", None)
                existing.setdefault("health_checked_at", None)
                if prev_host != host:
                    existing["host_reachable"] = None
                    existing["health_checked_at"] = None
            else:
                self._sessions[name] = {
                    "name": name,
                    "host": host,
                    "status": status,
                    "created_at": now,
                    "last_seen": now,
                    "host_reachable": None,
                    "health_checked_at": None,
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

    def set_host_reachable(self, name: str, reachable: bool) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            s = self._sessions.get(name)
            if not s:
                return False
            new_value = bool(reachable)
            if s.get("host_reachable") == new_value:
                return False
            s["host_reachable"] = new_value
            s["health_checked_at"] = now
            self._save()
            return True


class HistoryStore:
    """Thread-safe command history store with JSON file persistence."""

    def __init__(self, path: Path | None = None, max_len: int = 2000) -> None:
        self._path = path or _history_path()
        self._max_len = max_len
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self._lines = [x for x in data if isinstance(x, str)]
        except (FileNotFoundError, json.JSONDecodeError):
            self._lines = []

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._lines, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path)

    def list(self, limit: int | None = None) -> list[str]:
        with self._lock:
            lines = list(self._lines)
        if limit is not None and limit > 0:
            lines = lines[-limit:]
        return lines

    def append(self, line: str) -> None:
        s = (line or "").strip()
        if not s:
            return
        if len(s) > 4000:
            s = s[:4000]

        with self._lock:
            if self._lines and self._lines[-1] == s:
                return
            self._lines.append(s)
            if len(self._lines) > self._max_len:
                self._lines = self._lines[-self._max_len :]
            self._save()


class HealthChecker:
    """Periodically checks whether registered hosts are reachable."""

    def __init__(
        self,
        store: SessionStore,
        interval: float = 30.0,
        timeout: float = 2.0,
        probe_fn: Callable[[str, float], bool] = _probe_host,
    ) -> None:
        self._store = store
        self._interval = max(1.0, float(interval))
        self._timeout = max(0.1, float(timeout))
        self._probe_fn = probe_fn
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="zagora-health-check")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def run_once(self) -> None:
        host_cache: dict[str, bool] = {}
        for s in self._store.list():
            name = s.get("name")
            host = s.get("host")
            if not isinstance(name, str) or not isinstance(host, str) or not host:
                continue
            if host not in host_cache:
                try:
                    host_cache[host] = bool(self._probe_fn(host, self._timeout))
                except Exception:
                    host_cache[host] = False
            self._store.set_host_reachable(name, host_cache[host])

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self._stop.wait(self._interval)


def _make_handler(store: SessionStore, history: HistoryStore, token: str | None):
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

            u = urlparse(self.path)

            if u.path == "/sessions":
                q = parse_qs(u.query)
                host = None
                if "host" in q and q["host"]:
                    host = q["host"][0]
                sessions = store.list(host=host)
                self._json_response(200, sessions)
                return

            if u.path.startswith("/sessions/"):
                name = u.path.split("/sessions/", 1)[1]
                s = store.get(name)
                if s:
                    self._json_response(200, s)
                else:
                    self._json_response(404, {"error": "not found"})
                return

            if u.path == "/history":
                q = parse_qs(u.query)
                limit = None
                if "limit" in q and q["limit"]:
                    try:
                        limit = int(q["limit"][0])
                    except ValueError:
                        limit = None
                self._json_response(200, history.list(limit=limit))
                return

            if u.path == "/health":
                self._json_response(200, {"status": "ok"})
                return

            self._json_response(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._check_token():
                return

            u = urlparse(self.path)

            if u.path == "/sessions":
                body = self._read_json()
                name = body.get("name")
                host = body.get("host")
                if not name or not host:
                    self._json_response(400, {"error": "name and host required"})
                    return
                status = body.get("status", "running")
                s = store.register(name, host, status)
                self._json_response(200, s)
                return

            if u.path == "/history":
                body = self._read_json()
                line = body.get("line")
                if not isinstance(line, str) or not line.strip():
                    self._json_response(400, {"error": "line required"})
                    return
                history.append(line)
                self._json_response(200, {"ok": True})
                return

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


def run_server(
    port: int = 9876,
    token: str | None = None,
    bind: str = "0.0.0.0",
    health_interval: float = 30.0,
    health_timeout: float = 2.0,
) -> None:
    store = SessionStore()
    history = HistoryStore()
    handler = _make_handler(store, history, token)
    server = HTTPServer((bind, port), handler)
    checker: HealthChecker | None = None
    if health_interval > 0:
        checker = HealthChecker(store, interval=health_interval, timeout=health_timeout)
        checker.start()
    print(f"zagora server listening on {bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.shutdown()
        server.server_close()
        if checker is not None:
            checker.stop()
            checker.join(timeout=2)
