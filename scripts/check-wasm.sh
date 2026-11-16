#!/usr/bin/env bash
# Build frasil-wasm for wasm32-unknown-unknown and run, in Node.js, the vector
# tests of frasil-crypto, frasil-events, frasil-store and frasil-units again
# (crates/frasil-wasm/tests/vectors.rs) and frasil-crypto's randomness test.
#
# Installs nothing system-wide. wasm-bindgen-test-runner must be the version of
# wasm-bindgen in Cargo.lock: the one on the PATH if it is, otherwise one
# installed with `cargo install` into target/wasm-tools.
#
#   scripts/check-wasm.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() {
  echo "check-wasm: $*" >&2
  exit 1
}

target=wasm32-unknown-unknown

command -v cargo >/dev/null || fail "cargo is not installed; see https://rustup.rs"
command -v node >/dev/null || fail "Node.js is not installed; the tests run in Node.js 20 or later"
node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" -ge 20 ] || fail "Node.js $(node --version) is too old; use 20 or later"

sysroot="$(rustc --print sysroot)"
[ -d "$sysroot/lib/rustlib/$target" ] ||
  fail "the Rust standard library for $target is not installed; run: rustup target add $target"

# The test runner must match the wasm-bindgen the tests link exactly.
version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
[ -n "$version" ] || fail "no wasm-bindgen in Cargo.lock"
runner="$(command -v wasm-bindgen-test-runner || true)"
if [ -z "$runner" ] || [ "$("$runner" --version | awk '{ print $2 }')" != "$version" ]; then
  tools="$root/target/wasm-tools"
  runner="$tools/bin/wasm-bindgen-test-runner"
  if [ ! -x "$runner" ] || [ "$("$runner" --version | awk '{ print $2 }')" != "$version" ]; then
    echo "check-wasm: installing wasm-bindgen-test-runner $version into target/wasm-tools"
    cargo install --quiet --locked --force --root "$tools" wasm-bindgen-cli --version "$version"
  fi
fi

echo "check-wasm: building frasil-wasm for $target"
cargo build --locked --target "$target" -p frasil-wasm

echo "check-wasm: testing in Node.js $(node --version)"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$runner"
cargo test --locked --target "$target" -p frasil-crypto --test wasm_randomness
cargo test --locked --target "$target" -p frasil-wasm --test vectors
