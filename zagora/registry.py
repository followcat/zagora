"""HTTP client for the zagora registry server."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class RegistryError(RuntimeError):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


def _request(
    url: str,
    method: str = "GET",
    body: dict | None = None,
    token: str | None = None,
) -> Any:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except ValueError as e:
        raise RegistryError(f"invalid request: {e}") from None
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode())
        except Exception:
            detail = {}
        msg = detail.get("error", str(e))
        raise RegistryError(f"server returned {e.code}: {msg}", code=e.code) from None
    except urllib.error.URLError as e:
        raise RegistryError(f"cannot reach server: {e.reason}") from None


def _base(server: str) -> str:
    s = server.rstrip("/")
    if not s.startswith("http"):
        s = f"http://{s}"
    return s


def registry_ls(server: str, token: str | None = None, host: str | None = None) -> list[dict[str, Any]]:
    url = f"{_base(server)}/sessions"
    if host:
        url += "?" + urllib.parse.urlencode({"host": host})
    return _request(url, token=token)


def registry_get(
    server: str, name: str, token: str | None = None, host: str | None = None
) -> dict[str, Any]:
    url = f"{_base(server)}/sessions/{urllib.parse.quote(name, safe='')}"
    if host:
        url += "?" + urllib.parse.urlencode({"host": host})
    return _request(url, token=token)


def registry_register(
    server: str,
    name: str,
    host: str,
    token: str | None = None,
    status: str = "running",
) -> dict[str, Any]:
    url = f"{_base(server)}/sessions"
    return _request(url, method="POST", body={"name": name, "host": host, "status": status}, token=token)


def registry_remove(
    server: str, name: str, token: str | None = None, host: str | None = None
) -> dict[str, Any]:
    url = f"{_base(server)}/sessions/{urllib.parse.quote(name, safe='')}"
    if host:
        url += "?" + urllib.parse.urlencode({"host": host})
    return _request(url, method="DELETE", token=token)


def registry_history_list(server: str, token: str | None = None, limit: int | None = None) -> list[str]:
    url = f"{_base(server)}/history"
    if isinstance(limit, int) and limit > 0:
        url += f"?limit={limit}"
    data = _request(url, token=token)
    return [x for x in data if isinstance(x, str)]


def registry_history_add(server: str, line: str, token: str | None = None) -> None:
    url = f"{_base(server)}/history"
    _request(url, method="POST", body={"line": line}, token=token)
