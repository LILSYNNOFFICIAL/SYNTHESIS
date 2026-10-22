#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { printf 'SYNTHESIS build error: %s\n' "$*" >&2; exit 1; }
command -v node >/dev/null 2>&1 || fail "Node.js 20+ is required."
command -v npm >/dev/null 2>&1 || fail "npm is required."
command -v cargo >/dev/null 2>&1 || fail "Rust stable/Cargo is required."
command -v pkg-config >/dev/null 2>&1 || fail "pkg-config is required for Tauri Linux dependency checks."

NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 20 )) || fail "Node.js 20+ is required; found $(node --version)."

if ! pkg-config --exists webkit2gtk-4.1; then
  fail "Missing WebKitGTK development files. On Kali/Debian install Tauri prerequisites, including libwebkit2gtk-4.1-dev, build-essential, libssl-dev, libayatana-appindicator3-dev, and librsvg2-dev. See https://v2.tauri.app/start/prerequisites/#linux."
fi

printf '\n[1/5] Installing frontend dependencies\n'
npm install
printf '\n[2/5] Checking frontend types and production build\n'
npm run check
printf '\n[3/5] Formatting Rust source\n'
cargo fmt --manifest-path src-tauri/Cargo.toml --all
printf '\n[4/5] Running Rust tests\n'
cargo test --manifest-path src-tauri/Cargo.toml
printf '\n[5/5] Building desktop bundles\n'
npm run tauri build

printf '\nBuild command finished. Inspect bundle outputs under:\n%s/src-tauri/target/release/bundle\n' "$ROOT"
find "$ROOT/src-tauri/target/release/bundle" -type f \( -name '*.deb' -o -name '*.AppImage' \) -print 2>/dev/null || true
