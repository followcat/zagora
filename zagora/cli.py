from __future__ import annotations

import argparse
import shlex
import sys

from zagora.config import resolve_server, resolve_token
from zagora.exec import ZagoraError, exec_interactive, require_cmd, run_capture
from zagora.exec import ssh_via_tailscale, tailscale_ssh
from zagora.registry import (
    RegistryError,
    registry_get,
    registry_history_add,
    registry_history_list,
    registry_ls,
    registry_register,
    registry_remove,
)


BANNER = r"""
███████╗ █████╗  ██████╗  ██████╗ ██████╗  █████╗
╚══███╔╝██╔══██╗██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗
  ███╔╝ ███████║██║  ███╗██║   ██║██████╔╝███████║
 ███╔╝  ██╔══██║██║   ██║██║   ██║██╔══██╗██╔══██║
███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

zagora — centralized zellij sessions over tailscale
"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _zellij_install_script(install_dir: str) -> str:
    return f"""set -euo pipefail

if command -v zellij >/dev/null 2>&1; then
  echo 'zellij already installed'
  zellij --version || true
  exit 0
fi

os="$(uname -s)"
arch="$(uname -m)"
if [ "$os" != "Linux" ]; then
  echo "unsupported OS: $os" >&2
  exit 2
fi

case "$arch" in
  x86_64|amd64) target="x86_64-unknown-linux-musl" ;;
  aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
  *) echo "unsupported arch: $arch" >&2; exit 2 ;;
esac

url="https://github.com/zellij-org/zellij/releases/latest/download/zellij-${{target}}.tar.gz"

fetch() {{
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$1" "$url"
  else
    echo 'need curl or wget to download zellij' >&2
    exit 2
  fi
}}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch "$tmp/zellij.tgz"
mkdir -p "{install_dir}"
tar -xzf "$tmp/zellij.tgz" -C "$tmp"

if [ ! -f "$tmp/zellij" ]; then
  echo 'unexpected archive layout (missing zellij binary)' >&2
  exit 2
fi

install -m 0755 "$tmp/zellij" "{install_dir}/zellij"

echo "installed: {install_dir}/zellij"

# --- ensure zellij is in PATH for all shell sessions ---

binpath="{install_dir}"
# expand $HOME if present
case "$binpath" in
  \\$HOME/*) binpath="$HOME/${{binpath#\\$HOME/}}" ;;
esac

# try symlink into a system-wide bin (if writable, no sudo)
for sysbin in /usr/local/bin /usr/bin; do
  if [ -d "$sysbin" ] && [ -w "$sysbin" ]; then
    ln -sf "$binpath/zellij" "$sysbin/zellij" 2>/dev/null && \
      echo "symlinked: $sysbin/zellij -> $binpath/zellij" && break
  fi
done

# ensure install_dir is in PATH via shell profile
path_line='export PATH="'"$binpath"':$PATH"'

add_to_profile() {{
  local f="$1"
  if [ -f "$f" ] && grep -qF "$binpath" "$f" 2>/dev/null; then
    return
  fi
  # only write to files that already exist or whose parent dir exists
  if [ -f "$f" ] || [ -d "$(dirname "$f")" ]; then
    printf '\\n# Added by zagora install-zellij\\n%s\\n' "$path_line" >> "$f"
    echo "updated: $f"
  fi
}}

# detect current shell and update the right rc file
current_shell="$(basename "${{SHELL:-/bin/sh}}")"
case "$current_shell" in
  zsh)
    add_to_profile "$HOME/.zshrc"
    ;;
  bash)
    # prefer .bashrc (interactive), fall back to .profile
    if [ -f "$HOME/.bashrc" ]; then
      add_to_profile "$HOME/.bashrc"
    else
      add_to_profile "$HOME/.profile"
    fi
    ;;
  fish)
    fishconf="$HOME/.config/fish/config.fish"
    if [ -f "$fishconf" ] && grep -qF "$binpath" "$fishconf" 2>/dev/null; then
      :
    elif [ -d "$HOME/.config/fish" ]; then
      printf '\\n# Added by zagora install-zellij\\nset -gx PATH %s $PATH\\n' "$binpath" >> "$fishconf"
      echo "updated: $fishconf"
    fi
    ;;
  *)
    add_to_profile "$HOME/.profile"
    ;;
esac

echo "done — zellij is ready to use"
"""


def _normalize_server_url(server: str) -> str:
    s = server.rstrip("/")
    if not s.startswith("http"):
        # bare host or host:port → prepend scheme
        s = f"http://{s}"
        # add default port only if none specified
        if ":" not in s.split("//", 1)[1]:
            s = f"{s}:9876"
    return s


def _server_or_exit(args: argparse.Namespace) -> str:
    server = resolve_server(getattr(args, "host", None))
    if not server:
        raise ZagoraError(
            "missing server; provide --host, set ZAGORA_HOST, "
            'or set ~/.config/zagora/config.json {"server": "http://host:port"}'
        )
    return _normalize_server_url(server)


def _token(args: argparse.Namespace) -> str | None:
    return resolve_token(getattr(args, "token", None))


def _short_ts(ts: object) -> str:
    if not isinstance(ts, str) or not ts:
        return "-"
    s = ts.strip().replace("T", " ")
    if len(s) >= 19:
        return s[:19]
    return s


def _connect_or_exit(args: argparse.Namespace) -> str:
    c = getattr(args, "connect", None)
    if not c:
        raise ZagoraError("missing -c/--connect: specify the target machine")
    return c


_HOSTKEY_ERR = "No ED25519 host key is known for"


def _zellij_remote(argv: list[str]) -> list[str]:
    joined = " ".join(shlex.quote(a) for a in argv)
    script = (
        "if command -v zellij >/dev/null 2>&1; then "
        f"exec zellij {joined}; "
        'elif [ -x "$HOME/.local/bin/zellij" ]; then '
        f'exec "$HOME/.local/bin/zellij" {joined}; '
        'else echo "zellij not found; run: zagora install-zellij -c <host>" >&2; exit 127; fi'
    )
    # SSH concatenates remote_argv with spaces and feeds it to the remote
    # shell.  We must pass the script as a single shell-quoted token so
    # that `sh -lc <script>` keeps it intact (otherwise `sh -c` treats
    # the second word as $0, not part of the script).
    return ["sh", "-lc", shlex.quote(script)]


def _hostkey_problem(stderr: str) -> bool:
    return _HOSTKEY_ERR in (stderr or "") or "Host key verification failed" in (stderr or "")


def _tailscale_rejects_y(stderr: str) -> bool:
    s = stderr or ""
    return "flag provided but not defined: -Y" in s or "unknown shorthand flag: 'Y'" in s


def _transport(args: argparse.Namespace) -> str:
    return getattr(args, "transport", "auto")


def _run_remote_capture(args: argparse.Namespace, host: str, remote_argv: list[str]):
    t = _transport(args)
    if t == "ssh":
        return run_capture(ssh_via_tailscale(host, remote_argv))
    if t == "tailscale":
        p = run_capture(tailscale_ssh(host, remote_argv))
        if p.returncode != 0 and _tailscale_rejects_y(p.stderr):
            return run_capture(ssh_via_tailscale(host, remote_argv))
        return p

    p = run_capture(tailscale_ssh(host, remote_argv))
    if p.returncode != 0 and (_hostkey_problem(p.stderr) or _tailscale_rejects_y(p.stderr)):
        return run_capture(ssh_via_tailscale(host, remote_argv))
    return p


def _exec_remote_interactive(args: argparse.Namespace, host: str, remote_argv: list[str]) -> int:
    import subprocess
    import signal

    repl_mode = bool(getattr(args, "_repl_mode", False))

    def _run_or_exec(argv: list[str]) -> int:
        if repl_mode:
            old = signal.getsignal(signal.SIGINT)
            try:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                return subprocess.run(
                    argv,
                    check=False,
                    preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
                ).returncode
            finally:
                signal.signal(signal.SIGINT, old)
        exec_interactive(argv)
        return 0

    t = _transport(args)
    if t == "ssh":
        return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))
    if t == "tailscale":
        try:
            pre = subprocess.run(
                tailscale_ssh(host, ["true"]),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))

        if pre.returncode == 0:
            return _run_or_exec(tailscale_ssh(host, remote_argv, tty=True))
        if _tailscale_rejects_y(pre.stderr):
            sys.stderr.write("zagora: tailscale ssh does not support -Y; falling back to system ssh\n")
            return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))
        return _run_or_exec(tailscale_ssh(host, remote_argv, tty=True))

    # auto: quick preflight to detect host-key issues (no password prompt)
    try:
        pre = subprocess.run(
            tailscale_ssh(host, ["true"]),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        # tailscale ssh hung (probably waiting for something); fall back
        return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))

    if pre.returncode == 0:
        return _run_or_exec(tailscale_ssh(host, remote_argv, tty=True))
    if _tailscale_rejects_y(pre.stderr):
        sys.stderr.write("zagora: tailscale ssh does not support -Y; falling back to system ssh\n")
        return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))
    if _hostkey_problem(pre.stderr):
        sys.stderr.write("zagora: tailscale ssh host key unavailable; falling back to system ssh\n")
        return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))

    # other failure (e.g. host unreachable) — still try ssh fallback
    return _run_or_exec(ssh_via_tailscale(host, remote_argv, tty=True))


def _parse_zellij_ls_names(output: str) -> list[str]:
    """Parse `zellij ls` output into session names."""
    out: list[str] = []
    seen: set[str] = set()
    for line in (output or "").splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if (
            low.startswith("no active zellij session")
            or low.startswith("no zellij sessions")
            or low.startswith("no active sessions")
        ):
            continue
        first = s.split()[0]
        if first.lower() in {"name", "session", "sessions"}:
            continue
        if first not in seen:
            out.append(first)
            seen.add(first)
    return out


def _rewrite_repl_shorthand(argv: list[str]) -> list[str]:
    """Rewrite convenient REPL shorthand into regular CLI flags."""
    if not argv:
        return argv

    cmd = argv[0]
    rest = argv[1:]

    def _has_any(flags: tuple[str, ...]) -> bool:
        return any(x in rest for x in flags)

    # open <host> <session>
    if cmd == "open":
        if (
            not _has_any(("-c", "--connect", "-n", "--name"))
            and len(rest) == 2
            and all(not x.startswith("-") for x in rest)
        ):
            return ["open", "-c", rest[0], "-n", rest[1]]
        return argv

    # attach <session> [host] / kill <session> [host]
    if cmd in {"attach", "a", "kill"}:
        if (
            not _has_any(("-n", "--name", "-c", "--connect"))
            and 1 <= len(rest) <= 2
            and all(not x.startswith("-") for x in rest)
        ):
            out = [cmd, "-n", rest[0]]
            if len(rest) == 2:
                out += ["-c", rest[1]]
            return out
        return argv

    # ls <host> / refresh <host> / sync <host> / install-zellij <host>
    if cmd in {"ls", "refresh", "sync", "install-zellij"}:
        if (
            not _has_any(("-c", "--connect"))
            and len(rest) == 1
            and not rest[0].startswith("-")
        ):
            return [cmd, "-c", rest[0]]
        return argv

    return argv


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_completion(args: argparse.Namespace) -> int:
    shell = args.shell

    subs = "serve open attach a ls kill sync refresh update doctor install-zellij interactive i completion".split()
    global_opts = "--host --token --transport".split()

    # Per-subcommand options (short + long)
    opts: dict[str, list[str]] = {
        "serve": ["--port", "--bind", "--token", "--health-interval", "--health-timeout"],
        "open": ["-c", "--connect", "-n", "--name", *global_opts],
        "attach": ["-c", "--connect", "-n", "--name", *global_opts],
        "a": ["-c", "--connect", "-n", "--name", *global_opts],
        "ls": ["-c", "--connect", *global_opts],
        "kill": ["-c", "--connect", "-n", "--name", *global_opts],
        "sync": ["-c", "--connect", *global_opts],
        "refresh": [
            "-c",
            "--connect",
            "--prune",
            "--prune-unreachable",
            "--no-prune",
            "--no-prune-unreachable",
            "--dry-run",
            *global_opts,
        ],
        "update": ["--repo", "--ref", "--zip-url", "--force", "-q", "--quiet"],
        "doctor": [*global_opts],
        "install-zellij": ["-c", "--connect", "--dir", "--transport"],
        "interactive": [*global_opts],
        "i": [*global_opts],
        "completion": ["--shell"],
    }

    if shell in {"bash", "zsh"}:
        # zsh uses bashcompinit wrapper.
        zsh_prelude = """
#compdef zagora
autoload -U +X bashcompinit && bashcompinit
""" if shell == "zsh" else ""

        script = f"""{zsh_prelude}
_zagora_complete() {{
  local cur prev cmd
  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"
  prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"

  # find first non-flag word after possible global opts
  cmd=\"\"
  for w in \"${{COMP_WORDS[@]:1}}\"; do
    case \"$w\" in
      --host|--token|--transport) continue ;;
      --*) continue ;;
      -*) continue ;;
      *) cmd=\"$w\"; break ;;
    esac
  done

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W '{" ".join(subs)} {" ".join(global_opts)}' -- \"$cur\") )
    return 0
  fi

  # completing subcommand
  if [[ -z \"$cmd\" && \"$cur\" != -* ]]; then
    COMPREPLY=( $(compgen -W '{" ".join(subs)}' -- \"$cur\") )
    return 0
  fi

  # options for current command
  local words=\"\"
  words='{ " ".join(global_opts) }'
  if [[ -n \"$cmd\" ]]; then
    case \"$cmd\" in
"""
        for k, v in opts.items():
            script += f"      {k}) words=\"{' '.join(sorted(set(v)))}\" ;;;\n"

        script += """    esac
  fi

  if [[ \"$cur\" == -* ]]; then
    COMPREPLY=( $(compgen -W "$words" -- "$cur") )
    return 0
  fi

  COMPREPLY=()
  return 0
}}

complete -F _zagora_complete zagora
"""
        sys.stdout.write(script)
        return 0

    if shell == "fish":
        # Keep it simple/static.
        lines: list[str] = [
            "# fish completion for zagora",
            "complete -c zagora -f",
        ]
        for s in subs:
            lines.append(f"complete -c zagora -n '__fish_use_subcommand' -a '{s}'")
        for o in global_opts:
            lines.append(f"complete -c zagora -l {o.lstrip('-')} -r")
        sys.stdout.write("\n".join(lines) + "\n")
        return 0

    raise ZagoraError("unsupported shell; use: bash, zsh, fish")



def cmd_serve(args: argparse.Namespace) -> int:
    from zagora.server import run_server
    run_server(
        port=args.port,
        token=_token(args),
        bind=args.bind,
        health_interval=args.health_interval,
        health_timeout=args.health_timeout,
    )
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    server = _server_or_exit(args)
    token = _token(args)
    target = _connect_or_exit(args)
    name = args.name

    # prevent duplicate names (global uniqueness in registry)
    try:
        registry_get(server, name, token=token)
        raise ZagoraError(
            f"session '{name}' already exists in registry; use 'zagora attach -n {name}' or 'zagora kill -n {name}'"
        )
    except RegistryError as e:
        if getattr(e, "code", None) != 404:
            raise ZagoraError(f"cannot check session name uniqueness: {e}") from None

    # register with server before exec (exec replaces process)
    registry_register(server, name, target, token=token)

    remote = _zellij_remote(["attach", "--create", name])
    return _exec_remote_interactive(args, target, remote)


def cmd_attach(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    server = _server_or_exit(args)
    token = _token(args)
    name = args.name

    target = getattr(args, "connect", None)
    if not target:
        # look up from registry
        try:
            info = registry_get(server, name, token=token)
            target = info.get("host")
        except RegistryError as e:
            raise ZagoraError(f"cannot find session '{name}': {e}") from None
        if not target:
            raise ZagoraError(f"session '{name}' has no host in registry")

    remote = _zellij_remote(["attach", name])
    return _exec_remote_interactive(args, target, remote)


def cmd_ls(args: argparse.Namespace) -> int:
    server = _server_or_exit(args)
    token = _token(args)
    host_filter = getattr(args, "connect", None)

    try:
        sessions = registry_ls(server, token=token, host=host_filter)
    except RegistryError as e:
        sys.stderr.write(f"zagora: {e}\n")
        return 1

    if not sessions:
        sys.stdout.write("(no sessions)\n")
        return 0

    for s in sessions:
        status = s.get("status", "?")
        host = s.get("host", "?")
        name = s.get("name", "?")
        reach = s.get("host_reachable")
        reach_s = "?" if reach is None else ("up" if bool(reach) else "down")
        last_seen = _short_ts(s.get("last_seen"))
        checked = _short_ts(s.get("health_checked_at"))
        created = _short_ts(s.get("created_at"))
        sys.stdout.write(
            f"  {name}\t{host}\t{status}\thost:{reach_s}\tseen:{last_seen}\thealth:{checked}\tcreated:{created}\n"
        )
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    server = _server_or_exit(args)
    token = _token(args)
    name = args.name

    target = getattr(args, "connect", None)
    if not target:
        try:
            info = registry_get(server, name, token=token)
            target = info.get("host")
        except RegistryError as e:
            raise ZagoraError(f"cannot find session '{name}': {e}") from None
        if not target:
            raise ZagoraError(f"session '{name}' has no host in registry")

    remote = _zellij_remote(["kill-session", name])
    p = _run_remote_capture(args, target, remote)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        return p.returncode

    # remove from registry
    try:
        registry_remove(server, name, token=token)
    except RegistryError as e:
        sys.stderr.write(f"zagora: warning: failed to remove from registry: {e}\n")

    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    server = _server_or_exit(args)
    token = _token(args)
    target = _connect_or_exit(args)

    p = _run_remote_capture(args, target, _zellij_remote(["ls"]))
    if p.returncode != 0:
        sys.stderr.write(p.stderr or p.stdout)
        return p.returncode

    remote_names = _parse_zellij_ls_names(p.stdout or "")

    try:
        current_sessions = registry_ls(server, token=token, host=target)
    except RegistryError as e:
        sys.stderr.write(f"zagora: {e}\n")
        return 1

    current_names: set[str] = set()
    for s in current_sessions:
        n = s.get("name")
        if isinstance(n, str) and n:
            current_names.add(n)

    added = 0
    updated = 0
    removed = 0
    failed = 0

    for name in remote_names:
        try:
            registry_register(server, name, target, token=token, status="running")
            if name in current_names:
                updated += 1
            else:
                added += 1
        except RegistryError as e:
            failed += 1
            sys.stderr.write(f"zagora: warning: failed to register '{name}': {e}\n")

    remote_set = set(remote_names)
    stale = sorted(current_names - remote_set)
    for name in stale:
        try:
            registry_remove(server, name, token=token)
            removed += 1
        except RegistryError as e:
            failed += 1
            sys.stderr.write(f"zagora: warning: failed to remove stale '{name}': {e}\n")

    discovered = len(remote_names)
    sys.stdout.write(
        f"synced {target}: discovered {discovered}, added {added}, updated {updated}, removed {removed}\n"
    )
    if failed:
        sys.stderr.write(f"zagora: sync completed with {failed} errors\n")
        return 1
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    server = _server_or_exit(args)
    token = _token(args)
    host_filter = getattr(args, "connect", None)
    prune = (not getattr(args, "no_prune", False)) or getattr(args, "prune", False)
    prune_unreachable = (not getattr(args, "no_prune_unreachable", False)) or getattr(args, "prune_unreachable", False)
    dry_run = getattr(args, "dry_run", False)

    try:
        sessions = registry_ls(server, token=token, host=host_filter)
    except RegistryError as e:
        sys.stderr.write(f"zagora: {e}\n")
        return 1

    if not sessions:
        sys.stdout.write("(no sessions)\n")
        return 0

    removed = 0
    updated = 0

    for s in sessions:
        name = s.get("name")
        host = s.get("host")
        if not isinstance(name, str) or not isinstance(host, str) or not name or not host:
            continue

        p = _run_remote_capture(args, host, _zellij_remote(["ls"]))
        if p.returncode != 0:
            # host unreachable (or zellij missing)
            if prune_unreachable:
                sys.stdout.write(f"  - {name}\t{host}\tunreachable -> remove\n")
                if not dry_run:
                    try:
                        registry_remove(server, name, token=token)
                        removed += 1
                    except RegistryError:
                        pass
                continue

            new_status = "unreachable"
            if s.get("status") != new_status:
                sys.stdout.write(f"  ~ {name}\t{host}\t{new_status}\n")
                if not dry_run:
                    try:
                        registry_register(server, name, host, token=token, status=new_status)
                        updated += 1
                    except RegistryError:
                        pass
            continue

        remote_set = set(_parse_zellij_ls_names(p.stdout or ""))
        found = name in remote_set

        if found:
            new_status = "running"
            if s.get("status") != new_status:
                sys.stdout.write(f"  ~ {name}\t{host}\t{new_status}\n")
                if not dry_run:
                    try:
                        registry_register(server, name, host, token=token, status=new_status)
                        updated += 1
                    except RegistryError:
                        pass
            continue

        # reachable but session missing
        if prune:
            sys.stdout.write(f"  - {name}\t{host}\tmissing -> remove\n")
            if not dry_run:
                try:
                    registry_remove(server, name, token=token)
                    removed += 1
                except RegistryError:
                    pass
        else:
            new_status = "missing"
            if s.get("status") != new_status:
                sys.stdout.write(f"  ~ {name}\t{host}\t{new_status}\n")
                if not dry_run:
                    try:
                        registry_register(server, name, host, token=token, status=new_status)
                        updated += 1
                    except RegistryError:
                        pass

    if dry_run:
        sys.stdout.write(f"dry-run: would update {updated}, remove {removed}\n")
    else:
        sys.stdout.write(f"updated {updated}, removed {removed}\n")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """Self-update zagora from GitHub.

    Uses --force-reinstall so it can replace code even when the version
    number stays the same.
    """

    import importlib.metadata as md
    import json
    import os
    import subprocess
    import urllib.request
    from pathlib import Path

    repo = getattr(args, "repo", None) or os.environ.get("ZAGORA_INSTALL_REPO", "followcat/zagora")
    ref = getattr(args, "ref", None) or os.environ.get("ZAGORA_INSTALL_REF", "main")
    zip_url = getattr(args, "zip_url", None) or os.environ.get("ZAGORA_INSTALL_ZIP_URL")
    if not zip_url:
        zip_url = f"https://github.com/{repo}/archive/refs/heads/{ref}.zip"

    src = f"{repo}@{ref}"

    # keep a small marker so we can tell whether REF moved even if version doesn't
    data_home = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    prefix = Path(data_home) / "zagora"
    meta_file = prefix / "source.meta"

    before_ver = ""
    try:
        before_ver = md.version("zagora")
    except Exception:
        before_ver = ""

    before_src = ""
    before_sha = ""
    try:
        before_meta = meta_file.read_text(encoding="utf-8").strip()
        if before_meta:
            parts = before_meta.split(None, 1)
            before_src = parts[0]
            if len(parts) > 1:
                before_sha = parts[1].strip()
    except FileNotFoundError:
        pass
    except Exception:
        pass

    remote_sha = ""
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/commits/{ref}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "zagora",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        sha = data.get("sha")
        if isinstance(sha, str):
            remote_sha = sha
    except Exception:
        remote_sha = ""

    if remote_sha and not getattr(args, "force", False) and before_src == src and before_sha == remote_sha:
        short = remote_sha[:12]
        sys.stdout.write(f"zagora up-to-date: {src}@{short} (v{before_ver or '?'})\n")
        return 0

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "-U",
        "--force-reinstall",
        "--no-cache-dir",
        f"zagora @ {zip_url}",
    ]
    if getattr(args, "quiet", False):
        cmd.insert(4, "-q")

    p = subprocess.run(cmd, check=False)
    if p.returncode != 0:
        return p.returncode

    # Best-effort readline support for REPL history navigation.
    try:
        import readline  # noqa: F401
    except Exception:
        try:
            cmd2 = [sys.executable, "-m", "pip", "install", "-U", "gnureadline", "pyreadline3"]
            if getattr(args, "quiet", False):
                cmd2.insert(4, "-q")
            subprocess.run(cmd2, check=False)
        except Exception:
            pass

    after_ver = before_ver
    try:
        after_ver = md.version("zagora")
    except Exception:
        pass

    if remote_sha:
        try:
            prefix.mkdir(parents=True, exist_ok=True)
            meta_file.write_text(f"{src} {remote_sha}\n", encoding="utf-8")
        except Exception:
            pass

        short = remote_sha[:12]
        if before_sha and before_src == src and before_sha != remote_sha:
            sys.stdout.write(f"zagora updated: {before_sha[:12]} -> {short} (v{after_ver or '?'})\n")
        else:
            sys.stdout.write(f"zagora updated: {src}@{short} (v{after_ver or '?'})\n")
    else:
        if before_ver and after_ver and before_ver != after_ver:
            sys.stdout.write(f"zagora updated: v{before_ver} -> v{after_ver}\n")
        else:
            sys.stdout.write(f"zagora updated: v{after_ver or before_ver or '?'}\n")

    sys.stdout.write("note: restart 'zagora' to use updated code\n")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True
    for cmd in ("tailscale", "ssh"):
        try:
            require_cmd(cmd)
            sys.stdout.write(f"  ✓ {cmd}\n")
        except ZagoraError:
            sys.stdout.write(f"  ✗ {cmd} not found\n")
            ok = False

    p = run_capture(["tailscale", "version"])
    if p.returncode == 0:
        sys.stdout.write(f"  tailscale {p.stdout.strip().splitlines()[0]}\n")

    server = resolve_server(getattr(args, "host", None))
    if server:
        s = _normalize_server_url(server)
        try:
            from zagora.registry import _request
            _request(f"{s}/health", token=_token(args))
            sys.stdout.write(f"  ✓ server {s}\n")
        except Exception as e:
            sys.stdout.write(f"  ✗ server {s}: {e}\n")
            ok = False
    else:
        sys.stdout.write("  - server not configured\n")

    return 0 if ok else 1


def cmd_install_zellij(args: argparse.Namespace) -> int:
    require_cmd("tailscale")
    require_cmd("ssh")
    target = _connect_or_exit(args)

    install_dir = args.dir.replace("~", "$HOME", 1)
    script = _zellij_install_script(install_dir)
    remote = ["sh", "-lc", script]
    p = _run_remote_capture(args, target, remote)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        return p.returncode
    sys.stdout.write(p.stdout)
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def _add_common(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="zagora server address (http://host:port); can also use ZAGORA_HOST",
    )
    sub.add_argument(
        "--token",
        default=argparse.SUPPRESS,
        help="auth token for server; can also use ZAGORA_TOKEN",
    )
    sub.add_argument(
        "--transport",
        choices=["auto", "tailscale", "ssh"],
        default=argparse.SUPPRESS,
        help="SSH transport: auto (default), tailscale, ssh",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zagora",
        description="Manage zellij sessions across machines with a central registry",
    )
    p.add_argument("--host", help="zagora server address; can also use ZAGORA_HOST")
    p.add_argument("--token", help="auth token for server; can also use ZAGORA_TOKEN")
    p.add_argument(
        "--transport",
        choices=["auto", "tailscale", "ssh"],
        default="auto",
        help="SSH transport: auto (default), tailscale, ssh",
    )

    sp = p.add_subparsers(dest="cmd")

    # interactive
    p_i = sp.add_parser("interactive", aliases=["i"], help="interactive mode (REPL)")
    _add_common(p_i)
    p_i.set_defaults(func=_cmd_interactive)

    # completion
    p_comp = sp.add_parser("completion", help="print shell completion script")
    p_comp.add_argument("--shell", choices=["bash", "zsh", "fish"], default="bash")
    p_comp.set_defaults(func=cmd_completion)

    # serve
    p_serve = sp.add_parser("serve", help="start the zagora registry server")
    p_serve.add_argument("--port", type=int, default=9876, help="listen port (default: 9876)")
    p_serve.add_argument("--bind", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    p_serve.add_argument("--token", default=argparse.SUPPRESS, help="auth token")
    p_serve.add_argument(
        "--health-interval",
        type=float,
        default=30.0,
        help="host health-check interval seconds; 0 to disable (default: 30)",
    )
    p_serve.add_argument(
        "--health-timeout",
        type=float,
        default=2.0,
        help="host health-check timeout seconds (default: 2)",
    )
    p_serve.set_defaults(func=cmd_serve)

    # open
    p_open = sp.add_parser("open", help="create and attach to a zellij session on target machine")
    _add_common(p_open)
    p_open.add_argument("-c", "--connect", required=True, help="target machine (SSH target)")
    p_open.add_argument("-n", "--name", required=True, help="session name")
    p_open.set_defaults(func=cmd_open)

    # attach
    p_attach = sp.add_parser(
        "attach",
        aliases=["a"],
        help="attach to an existing session (auto-discovers host)",
    )
    _add_common(p_attach)
    p_attach.add_argument("-c", "--connect", help="target machine (optional; auto-discovered from registry)")
    p_attach.add_argument("-n", "--name", required=True, help="session name")
    p_attach.set_defaults(func=cmd_attach)

    # ls
    p_ls = sp.add_parser("ls", help="list all sessions from registry")
    _add_common(p_ls)
    p_ls.add_argument("-c", "--connect", help="filter by target machine")
    p_ls.set_defaults(func=cmd_ls)

    # kill
    p_kill = sp.add_parser("kill", help="kill a session (auto-discovers host)")
    _add_common(p_kill)
    p_kill.add_argument("-c", "--connect", help="target machine (optional; auto-discovered)")
    p_kill.add_argument("-n", "--name", required=True, help="session name")
    p_kill.set_defaults(func=cmd_kill)

    # sync
    p_sync = sp.add_parser("sync", help="scan target machine zellij sessions and sync to registry")
    _add_common(p_sync)
    p_sync.add_argument("-c", "--connect", required=True, help="target machine to scan")
    p_sync.set_defaults(func=cmd_sync)

    # refresh
    p_ref = sp.add_parser(
        "refresh",
        help="refresh session status; auto-prune invalid entries by default",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  zagora refresh\n"
            "  zagora refresh --dry-run\n"
            "  zagora refresh --no-prune\n"
            "  zagora refresh --no-prune-unreachable\n"
        ),
    )
    _add_common(p_ref)
    p_ref.add_argument("-c", "--connect", help="only refresh sessions on a specific host")
    p_ref.add_argument("--prune", action="store_true", help="deprecated alias (pruning is now default)")
    p_ref.add_argument(
        "--prune-unreachable",
        action="store_true",
        help="deprecated alias (unreachable pruning is now default)",
    )
    p_ref.add_argument("--no-prune", action="store_true", help="keep missing sessions; mark status as missing")
    p_ref.add_argument(
        "--no-prune-unreachable",
        action="store_true",
        help="keep unreachable sessions; mark status as unreachable",
    )
    p_ref.add_argument("--dry-run", action="store_true", help="print actions without writing to server")
    p_ref.set_defaults(func=cmd_refresh)

    # update
    p_up = sp.add_parser(
        "update",
        help="update zagora client (force-reinstall from GitHub)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  zagora update\n"
            "  zagora update --force\n"
            "  zagora update --ref main\n"
        ),
    )
    p_up.add_argument("--repo", help="GitHub repo (owner/repo); env: ZAGORA_INSTALL_REPO")
    p_up.add_argument("--ref", help="Git ref/branch; env: ZAGORA_INSTALL_REF")
    p_up.add_argument("--zip-url", help="override zip url; env: ZAGORA_INSTALL_ZIP_URL")
    p_up.add_argument("--force", action="store_true", help="force reinstall even if up-to-date")
    p_up.add_argument("-q", "--quiet", action="store_true", help="quiet pip output")
    p_up.set_defaults(func=cmd_update)

    # doctor
    p_doc = sp.add_parser("doctor", help="check prerequisites and server connectivity")
    _add_common(p_doc)
    p_doc.set_defaults(func=cmd_doctor)

    # install-zellij
    p_inst = sp.add_parser("install-zellij", help="install zellij on a remote machine")
    p_inst.add_argument("-c", "--connect", required=True, help="target machine")
    p_inst.add_argument(
        "--transport",
        choices=["auto", "tailscale", "ssh"],
        default=argparse.SUPPRESS,
        help="SSH transport",
    )
    p_inst.add_argument("--dir", default="~/.local/bin", help="install dir (default: ~/.local/bin)")
    p_inst.set_defaults(func=cmd_install_zellij)

    return p


def _cmd_interactive(args: argparse.Namespace) -> int:
    base: list[str] = []
    if getattr(args, "host", None):
        base += ["--host", str(args.host)]
    if getattr(args, "token", None):
        base += ["--token", str(args.token)]
    if getattr(args, "transport", None):
        base += ["--transport", str(args.transport)]

    parser = build_parser()

    server_raw = resolve_server(getattr(args, "host", None))
    server = _normalize_server_url(server_raw) if server_raw else None
    token = resolve_token(getattr(args, "token", None))

    readline = None
    try:
        import readline as _readline  # type: ignore

        readline = _readline
    except Exception:
        try:
            import gnureadline as _readline  # type: ignore

            readline = _readline
        except Exception:
            readline = None

    if readline:
        repl_cmds = [
            "ls",
            "open",
            "attach",
            "a",
            "kill",
            "sync",
            "refresh",
            "update",
            "doctor",
            "install-zellij",
            "help",
            "exit",
            "quit",
            "q",
        ]
        repl_opts: dict[str, list[str]] = {
            "ls": ["-c", "--connect"],
            "open": ["-c", "--connect", "-n", "--name"],
            "attach": ["-c", "--connect", "-n", "--name"],
            "a": ["-c", "--connect", "-n", "--name"],
            "kill": ["-c", "--connect", "-n", "--name"],
            "sync": ["-c", "--connect"],
            "refresh": [
                "-c",
                "--connect",
                "--prune",
                "--prune-unreachable",
                "--no-prune",
                "--no-prune-unreachable",
                "--dry-run",
            ],
            "update": ["--repo", "--ref", "--zip-url", "--force", "-q", "--quiet"],
            "doctor": [],
            "install-zellij": ["-c", "--connect", "--transport", "--dir"],
        }

        def _repl_complete(text: str, state: int):
            try:
                buf = readline.get_line_buffer()
                begidx = readline.get_begidx()
            except Exception:
                buf = ""
                begidx = 0

            head = buf[:begidx]
            try:
                parts = shlex.split(head)
            except ValueError:
                parts = head.split()

            candidates: list[str]
            if not parts:
                candidates = [c for c in repl_cmds if c.startswith(text)]
            elif len(parts) == 1 and not head.endswith(" "):
                candidates = [c for c in repl_cmds if c.startswith(text)]
            else:
                cmd = parts[0]
                if text.startswith("-"):
                    candidates = [o for o in repl_opts.get(cmd, []) if o.startswith(text)]
                else:
                    candidates = []

            candidates = sorted(set(candidates))
            if state < len(candidates):
                return candidates[state]
            return None

        try:
            readline.set_completer_delims(" \t\n")
            readline.set_completer(_repl_complete)
            try:
                readline.parse_and_bind("tab: complete")
            except Exception:
                readline.parse_and_bind("bind ^I rl_complete")
        except Exception:
            pass

    if readline and server:
        try:
            for h in registry_history_list(server, token=token, limit=2000):
                try:
                    readline.add_history(h)
                except Exception:
                    pass
        except Exception:
            # server unreachable
            pass

    sys.stdout.write(
        BANNER
        + "\n"
        + "interactive mode (shared history via server)\n"
        + "Commands: ls, open, attach(a), kill, sync, refresh, update, doctor, install-zellij\n"
        + "Maintenance: sync -c <host> / refresh(auto-prune) / update\n"
        + "Type 'help' for full help, Tab for completion, 'exit' to quit.\n\n"
    )

    while True:
        try:
            line = input("zagora> ").strip()
        except EOFError:
            sys.stdout.write("\n")
            return 0
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            continue

        if not line:
            continue
        if line in {"exit", "quit", "q"}:
            return 0
        if line in {"help", "h", "?"}:
            parser.print_help()
            continue

        if readline:
            try:
                n = readline.get_current_history_length()
                last = readline.get_history_item(n) if n > 0 else None
                if last != line:
                    readline.add_history(line)
            except Exception:
                pass

        if server:
            try:
                registry_history_add(server, line, token=token)
            except Exception:
                pass

        try:
            line_argv = _rewrite_repl_shorthand(shlex.split(line))
            argv2 = base + line_argv
        except ValueError as e:
            sys.stderr.write(f"zagora: {e}\n")
            continue

        # Avoid nesting interactive mode
        if line_argv and line_argv[0] in {"interactive", "i"}:
            sys.stderr.write("zagora: already in interactive mode\n")
            continue

        try:
            args2 = parser.parse_args(argv2)
            if not getattr(args2, "cmd", None):
                continue
            setattr(args2, "_repl_mode", True)
            func = getattr(args2, "func", None)
            if not func:
                sys.stderr.write("zagora: unknown command\n")
                continue
            rc = func(args2)
            if isinstance(rc, int) and rc != 0:
                sys.stderr.write(f"zagora: command exited with {rc}\n")
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            continue
        except SystemExit:
            # argparse error; keep REPL running
            continue
        except (ZagoraError, RegistryError) as e:
            sys.stderr.write(f"zagora: {e}\n")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no subcommand is provided, enter interactive mode.
    if not getattr(args, "cmd", None):
        raise SystemExit(_cmd_interactive(args))

    try:
        rc = args.func(args)
    except ZagoraError as e:
        sys.stderr.write(f"zagora: {e}\n")
        raise SystemExit(2)
    except RegistryError as e:
        sys.stderr.write(f"zagora: {e}\n")
        raise SystemExit(2)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
