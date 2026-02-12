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
python3 -m venv "$VENV"

"$VENV/bin/python" -m pip -q install -U pip setuptools wheel
"$VENV/bin/python" -m pip -q install -U "zagora @ ${ZIP_URL}"

# Best-effort readline support for REPL history navigation.
if ! "$VENV/bin/python" -c 'import readline' >/dev/null 2>&1; then
  echo "note: Python readline module not available; installing fallback (best-effort)" >&2
  "$VENV/bin/python" -m pip -q install -U gnureadline pyreadline3 || true
fi

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/zagora" "$BIN_DIR/zagora"

echo "installed: $BIN_DIR/zagora"

# Ensure ~/.local/bin in PATH (best-effort; idempotent)
path_line='export PATH="$HOME/.local/bin:$PATH"'

add_to_profile() {
  local f="$1"
  if [ -f "$f" ] && grep -qF "$HOME/.local/bin" "$f" 2>/dev/null; then
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
    if [ -f "$fishconf" ] && grep -qF "$HOME/.local/bin" "$fishconf" 2>/dev/null; then
      :
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
