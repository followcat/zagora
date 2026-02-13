from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


CONFIG_ENV_HOST = "ZAGORA_HOST"
CONFIG_ENV_TOKEN = "ZAGORA_TOKEN"
CONFIG_ENV_SSH_CONTROL_PERSIST = "ZAGORA_SSH_CONTROL_PERSIST"


def _xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))


def config_path() -> Path:
    return _xdg_config_home() / "zagora" / "config.json"


def load_config() -> dict[str, Any]:
    p = config_path()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def resolve_server(cli_server: str | None) -> str | None:
    """Resolve zagora server address.  Priority: CLI > env > config."""
    if cli_server and cli_server.strip():
        return cli_server.strip()

    env = os.environ.get(CONFIG_ENV_HOST)
    if isinstance(env, str) and env.strip():
        return env.strip()

    cfg = load_config()
    server = cfg.get("server")
    if isinstance(server, str) and server.strip():
        return server.strip()

    return None


def resolve_token(cli_token: str | None = None) -> str | None:
    """Resolve auth token.  Priority: CLI > env > config."""
    if cli_token and cli_token.strip():
        return cli_token.strip()

    env = os.environ.get(CONFIG_ENV_TOKEN)
    if isinstance(env, str) and env.strip():
        return env.strip()

    cfg = load_config()
    token = cfg.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()

    return None


def resolve_ssh_control_persist(cli_value: str | None = None) -> str:
    """Resolve SSH ControlPersist duration. Priority: CLI > env > config > default."""
    if isinstance(cli_value, str) and cli_value.strip():
        return cli_value.strip()

    env = os.environ.get(CONFIG_ENV_SSH_CONTROL_PERSIST)
    if isinstance(env, str) and env.strip():
        return env.strip()

    cfg = load_config()
    value = cfg.get("ssh_control_persist")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)):
        return str(int(value))

    return "120"
