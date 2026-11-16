#!/usr/bin/env bash
# Check the Tauri bridge (bindings/tauri), a workspace of its own: format,
# Clippy, its tests on Tauri's mock runtime, and cargo deny with its own
# deny.toml. It builds no webview.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/bindings/tauri"

cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny check
