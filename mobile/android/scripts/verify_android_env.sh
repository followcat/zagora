#!/usr/bin/env bash
set -euo pipefail

echo "[verify] checking Java..."
if ! command -v java >/dev/null 2>&1; then
  echo "java not found" >&2
  exit 2
fi

java_ver="$(java -version 2>&1 | head -n 1)"
echo "[verify] java: $java_ver"
if ! java -version 2>&1 | grep -Eq 'version "17\.|version "18\.|version "19\.|version "2[0-9]\.'; then
  echo "JDK 17+ is required for this Android project" >&2
  exit 2
fi

echo "[verify] checking Android SDK path..."
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "${sdk}" ]]; then
  echo "ANDROID_SDK_ROOT/ANDROID_HOME is not set" >&2
  exit 2
fi
if [[ ! -d "${sdk}" ]]; then
  echo "Android SDK path does not exist: ${sdk}" >&2
  exit 2
fi
echo "[verify] sdk: ${sdk}"

echo "[verify] OK"

