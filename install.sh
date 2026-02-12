#!/usr/bin/env bash
set -euo pipefail

# One-line installer for the zagora client.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/followcat/zagora/main/install.sh | bash
#
# Override source:
#   ZAGORA_INSTALL_REPO=owner/repo ZAGORA_INSTALL_REF=main bash install.sh
#   ZAGORA_INSTALL_ZIP_URL=https://github.com/owner/repo/archive/refs/tags/v0.0.1.zip bash install.sh

REPO="${ZAGORA_INSTALL_REPO:-followcat/zagora}"
REF="${ZAGORA_INSTALL_REF:-main}"
ZIP_URL="${ZAGORA_INSTALL_ZIP_URL:-https://github.com/${REPO}/archive/refs/heads/${REF}.zip}"

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
PREFIX="$DATA_HOME/zagora"
VENV="$PREFIX/venv"
BIN_DIR="$HOME/.local/bin"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

need python3

mkdir -p "$PREFIX"

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi

get_zagora_version() {
  "$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("zagora"))' 2>/dev/null || true
}

get_remote_sha() {
  ZAGORA_REPO="$REPO" ZAGORA_REF="$REF" "$VENV/bin/python" - <<'PY'
import json
import os
import urllib.request

repo = os.environ.get("ZAGORA_REPO", "")
ref = os.environ.get("ZAGORA_REF", "")
if not repo or not ref:
    raise SystemExit(0)

url = f"https://api.github.com/repos/{repo}/commits/{ref}"
try:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "zagora-installer",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.load(resp)
    sha = data.get("sha", "")
    if isinstance(sha, str) and sha:
        print(sha)
except Exception:
    pass
PY
}

meta_file="$PREFIX/source.meta"

before_ver="$(get_zagora_version)"
before_meta="$(cat "$meta_file" 2>/dev/null || true)"
before_src=""
before_sha=""
if [ -n "$before_meta" ]; then
  before_src="${before_meta%% *}"
  before_sha="${before_meta#* }"
fi

src="${REPO}@${REF}"
remote_sha="$(get_remote_sha)"

"$VENV/bin/python" -m pip -q install -U pip setuptools wheel
# Always replace code even if project version is unchanged.
"$VENV/bin/python" -m pip -q install -U --force-reinstall --no-cache-dir "zagora @ ${ZIP_URL}"

# Best-effort readline support for REPL history navigation.
if ! "$VENV/bin/python" -c 'import readline' >/dev/null 2>&1; then
  echo "note: Python readline module not available; installing fallback (best-effort)" >&2
  "$VENV/bin/python" -m pip -q install -U gnureadline pyreadline3 || true
fi

after_ver="$(get_zagora_version)"

if [ -n "$remote_sha" ]; then
  echo "${src} ${remote_sha}" > "$meta_file" 2>/dev/null || true
  new_short="${remote_sha:0:12}"
  if [ -n "$before_sha" ] && [ "$before_src" = "$src" ] && [ "$before_sha" != "$remote_sha" ]; then
    echo "zagora updated: ${before_sha:0:12} -> $new_short (v$after_ver)"
  elif [ -z "$before_ver" ] && [ -n "$after_ver" ]; then
    echo "zagora installed: $src@$new_short (v$after_ver)"
  else
    echo "zagora up-to-date: $src@$new_short (v$after_ver)"
  fi
else
  if [ -z "$before_ver" ] && [ -n "$after_ver" ]; then
    echo "zagora installed: v$after_ver"
  elif [ -n "$before_ver" ] && [ -n "$after_ver" ] && [ "$before_ver" = "$after_ver" ]; then
    echo "zagora refreshed: v$after_ver"
  elif [ -n "$before_ver" ] && [ -n "$after_ver" ]; then
    echo "zagora updated: v$before_ver -> v$after_ver"
  else
    echo "zagora installed/updated"
  fi
fi

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/zagora" "$BIN_DIR/zagora"

echo "linked: $BIN_DIR/zagora"

# Ensure ~/.local/bin in PATH (best-effort; idempotent)
path_line='export PATH="$HOME/.local/bin:$PATH"'

add_to_profile() {
  local f="$1"
  if [ -f "$f" ] && grep -qF ".local/bin" "$f" 2>/dev/null; then
    echo "ok: $f already has ~/.local/bin in PATH"
    return
  fi
  if [ -f "$f" ] || [ -d "$(dirname "$f")" ]; then
    printf '\n# Added by zagora installer\n%s\n' "$path_line" >> "$f"
    echo "updated: $f"
  fi
}

current_shell="$(basename "${SHELL:-/bin/sh}")"
case "$current_shell" in
  zsh)
    add_to_profile "$HOME/.zshrc"
    ;;
  bash)
    if [ -f "$HOME/.bashrc" ]; then
      add_to_profile "$HOME/.bashrc"
    else
      add_to_profile "$HOME/.profile"
    fi
    ;;
  fish)
    fishconf="$HOME/.config/fish/config.fish"
    if [ -f "$fishconf" ] && grep -qF ".local/bin" "$fishconf" 2>/dev/null; then
      echo "ok: $fishconf already has ~/.local/bin in PATH"
    elif [ -d "$HOME/.config/fish" ]; then
      printf '\n# Added by zagora installer\nset -gx PATH $HOME/.local/bin $PATH\n' >> "$fishconf"
      echo "updated: $fishconf"
    fi
    ;;
  *)
    add_to_profile "$HOME/.profile"
    ;;
esac

echo "done — open a new shell or 'source' your rc file to use 'zagora'"
