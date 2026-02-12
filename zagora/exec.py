from __future__ import annotations

import os
import shutil
import subprocess
from typing import NoReturn
from typing import Sequence


class ZagoraError(RuntimeError):
    pass


def require_cmd(cmd: str) -> str:
    p = shutil.which(cmd)
    if not p:
        raise ZagoraError(f"required command not found in PATH: {cmd}")
    return p


def run_capture(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), text=True, capture_output=True, check=False)


def exec_interactive(argv: Sequence[str]) -> NoReturn:
    # Replace current process to preserve TTY behavior (for zellij attach).
    os.execvp(argv[0], list(argv))


def _tailscale_ip(host: str) -> str:
    # Best-effort: resolve MagicDNS name to a stable Tailscale IP.
    try:
        if shutil.which("tailscale") is None:
            return host
        p = run_capture(["tailscale", "ip", "-4", host])
        if p.returncode != 0:
            return host
        ip = (p.stdout.strip().splitlines() or [""])[0].strip()
        return ip or host
    except Exception:
        return host


def tailscale_ssh(host: str, remote_argv: Sequence[str], *, tty: bool = False) -> list[str]:
    cmd = ["tailscale", "ssh", "-Y"]
    if tty:
        cmd.append("-t")
    cmd += [host, "--", *remote_argv]
    return cmd


def ssh_via_tailscale(host: str, remote_argv: Sequence[str], *, tty: bool = False) -> list[str]:
    h = _tailscale_ip(host)
    cmd = [
        "ssh",
        "-Y",
        "-o",
        "ProxyCommand=tailscale nc %h %p",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if tty:
        cmd.append("-t")
    cmd += [h, "--", *remote_argv]
    return cmd
