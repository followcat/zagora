from __future__ import annotations

import argparse
import shlex
import sys

from zagora.config import resolve_server, resolve_token
from zagora.exec import ZagoraError, exec_interactive, require_cmd, run_capture
from zagora.exec import ssh_via_tailscale, tailscale_ssh
from zagora.registry import RegistryError, registry_get, registry_ls, registry_register, registry_remove


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


def _server_or_exit(args: argparse.Namespace) -> str:
    server = resolve_server(getattr(args, "host", None))
    if not server:
        raise ZagoraError(
            "missing server; provide --host, set ZAGORA_HOST, "
            'or set ~/.config/zagora/config.json {"server": "http://host:port"}'
        )
    s = server.rstrip("/")
    if not s.startswith("http"):
        # bare host or host:port → prepend scheme
        s = f"http://{s}"
        # add default port only if none specified
        if ":" not in s.split("//", 1)[1]:
            s = f"{s}:9876"
    return s


def _token(args: argparse.Namespace) -> str | None:
    return resolve_token(getattr(args, "token", None))


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


def _transport(args: argparse.Namespace) -> str:
    return getattr(args, "transport", "auto")


def _run_remote_capture(args: argparse.Namespace, host: str, remote_argv: list[str]):
    t = _transport(args)
    if t == "ssh":
        return run_capture(ssh_via_tailscale(host, remote_argv))
    if t == "tailscale":
        return run_capture(tailscale_ssh(host, remote_argv))

    p = run_capture(tailscale_ssh(host, remote_argv))
    if p.returncode != 0 and _hostkey_problem(p.stderr):
        return run_capture(ssh_via_tailscale(host, remote_argv))
    return p


def _exec_remote_interactive(args: argparse.Namespace, host: str, remote_argv: list[str]) -> int:
    t = _transport(args)
    if t == "ssh":
        exec_interactive(ssh_via_tailscale(host, remote_argv, tty=True))
    if t == "tailscale":
        exec_interactive(tailscale_ssh(host, remote_argv, tty=True))

    # auto: quick preflight to detect host-key issues (no password prompt)
    import subprocess
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
        exec_interactive(ssh_via_tailscale(host, remote_argv, tty=True))

    if pre.returncode == 0:
        exec_interactive(tailscale_ssh(host, remote_argv, tty=True))
    if _hostkey_problem(pre.stderr):
        sys.stderr.write("zagora: tailscale ssh host key unavailable; falling back to system ssh\n")
        exec_interactive(ssh_via_tailscale(host, remote_argv, tty=True))

    # other failure (e.g. host unreachable) — still try ssh fallback
    exec_interactive(ssh_via_tailscale(host, remote_argv, tty=True))


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_serve(args: argparse.Namespace) -> int:
    from zagora.server import run_server
    run_server(port=args.port, token=_token(args), bind=args.bind)
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
        sys.stdout.write(f"  {name}\t{host}\t{status}\n")
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
        s = server.rstrip("/")
        if not s.startswith("http"):
            s = f"http://{s}:9876"
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

    # serve
    p_serve = sp.add_parser("serve", help="start the zagora registry server")
    p_serve.add_argument("--port", type=int, default=9876, help="listen port (default: 9876)")
    p_serve.add_argument("--bind", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    p_serve.add_argument("--token", default=argparse.SUPPRESS, help="auth token")
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

    sys.stdout.write(
        "zagora interactive mode\n"
        "Commands: ls, open, attach(a), kill, doctor, install-zellij\n"
        "Type 'help' for full help, 'exit' to quit.\n\n"
    )

    while True:
        try:
            line = input("zagora> ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write("\n")
            return 0

        if not line:
            continue
        if line in {"exit", "quit", "q"}:
            return 0
        if line in {"help", "h", "?"}:
            parser.print_help()
            continue

        try:
            argv2 = base + shlex.split(line)
        except ValueError as e:
            sys.stderr.write(f"zagora: {e}\n")
            continue

        # Avoid nesting interactive mode
        if argv2 and argv2[-1] in {"interactive", "i"}:
            sys.stderr.write("zagora: already in interactive mode\n")
            continue

        try:
            args2 = parser.parse_args(argv2)
            if not getattr(args2, "cmd", None):
                continue
            func = getattr(args2, "func", None)
            if not func:
                sys.stderr.write("zagora: unknown command\n")
                continue
            rc = func(args2)
            if isinstance(rc, int) and rc != 0:
                sys.stderr.write(f"zagora: command exited with {rc}\n")
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
