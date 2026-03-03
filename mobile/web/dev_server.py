#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.server
import json
import mimetypes
import os
import socketserver
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Handler(http.server.BaseHTTPRequestHandler):
    upstream: str = ""

    def log_message(self, fmt: str, *args) -> None:
        pass

    def _proxy(self) -> None:
        assert self.upstream
        path = self.path[len("/api") :] if self.path.startswith("/api") else self.path
        if not path.startswith("/"):
            path = "/" + path
        target = self.upstream.rstrip("/") + path

        body = b""
        if self.command in {"POST", "PUT", "PATCH"}:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n > 0:
                body = self.rfile.read(n)

        headers = {}
        auth = self.headers.get("Authorization")
        ctype = self.headers.get("Content-Type")
        if auth:
            headers["Authorization"] = auth
        if ctype:
            headers["Content-Type"] = ctype

        req = urllib.request.Request(target, data=body if body else None, method=self.command, headers=headers)
        try:
            with NO_PROXY_OPENER.open(req, timeout=8) as resp:
                data = resp.read()
                self.send_response(resp.getcode())
                for k, v in resp.headers.items():
                    lk = k.lower()
                    if lk in {"transfer-encoding", "connection", "content-encoding"}:
                        continue
                    self.send_header(k, v)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    return
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                self.wfile.write(data or json.dumps({"error": str(e)}).encode())
            except (BrokenPipeError, ConnectionResetError):
                return
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                self.wfile.write(json.dumps({"error": f"proxy failed: {e}"}).encode())
            except (BrokenPipeError, ConnectionResetError):
                return

    def _serve_file(self) -> None:
        rel = self.path.split("?", 1)[0]
        rel = "index.html" if rel in {"/", ""} else rel.lstrip("/")
        fp = (ROOT / rel).resolve()
        if ROOT not in fp.parents and fp != ROOT:
            self.send_error(403)
            return
        if not fp.exists() or not fp.is_file():
            self.send_error(404)
            return
        ctype, _ = mimetypes.guess_type(str(fp))
        self.send_response(200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.end_headers()
        try:
            self.wfile.write(fp.read_bytes())
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_OPTIONS(self) -> None:  # noqa: N802
        if self.path.startswith("/api"):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.end_headers()
            return
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/api"):
            self._proxy()
            return
        self._serve_file()

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/api"):
            self._proxy()
            return
        self.send_error(405)

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.startswith("/api"):
            self._proxy()
            return
        self.send_error(405)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4173)
    ap.add_argument("--upstream", default=os.environ.get("ZAGORA_UPSTREAM", "http://127.0.0.1:9876"))
    args = ap.parse_args()

    Handler.upstream = args.upstream.rstrip("/")
    with socketserver.ThreadingTCPServer(("127.0.0.1", args.port), Handler) as srv:
        print(f"web dev server: http://127.0.0.1:{args.port}")
        print(f"api proxy: /api -> {Handler.upstream}")
        srv.serve_forever()


if __name__ == "__main__":
    main()
