#!/usr/bin/env bash
# Benchmarks the browser package's WebAssembly module at one or more opt-levels of the
# `wasm-release` profile, in Node.js and in headless Chromium, and prints a table of median times:
# opening a device, importing and merging a large document, applying many small updates, signing
# and verifying events of both signature schemes, and resolving a space with many roster events
# (packages/frasil/bench/workloads.mjs).
#
# Each opt-level builds the package from a clean state into target/bench-wasm/<level>/ (the module
# twice, with and without the index, as scripts/build.mjs does), with the profile's opt-level set
# by CARGO_PROFILE_WASM_RELEASE_OPT_LEVEL. Cargo.toml and dist/ are not touched. Needs what
# scripts/check-js.sh needs (wasm-bindgen at the pinned version, the pnpm install), and, for
# Chromium, `pnpm --dir packages/frasil exec playwright install chromium`.
#
#   scripts/bench-wasm.sh                      opt-levels s and z, Node.js and Chromium, 7 runs
#   scripts/bench-wasm.sh --levels s,z,3       other opt-levels
#   scripts/bench-wasm.sh --runs 15            more timed runs of each workload
#   scripts/bench-wasm.sh --engines node       Node.js only (or: chromium)
#   scripts/bench-wasm.sh --no-build           run again on the last builds
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

levels="s,z"
runs=7
engines="node,chromium"
build=1
while [ $# -gt 0 ]; do
  case "$1" in
    --levels)
      levels="${2:?--levels takes a comma-separated list}"
      shift 2
      ;;
    --runs)
      runs="${2:?--runs takes a number}"
      shift 2
      ;;
    --engines)
      engines="${2:?--engines takes a comma-separated list}"
      shift 2
      ;;
    --no-build)
      build=0
      shift
      ;;
    -h | --help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "bench-wasm: unknown argument $1 (try --help)" >&2
      exit 2
      ;;
  esac
done

version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
bindgen="${WASM_BINDGEN:-}"
if [ -z "$bindgen" ]; then
  bindgen="$(command -v wasm-bindgen || true)"
  if [ -z "$bindgen" ] || [ "$("$bindgen" --version | awk '{ print $2 }')" != "$version" ]; then
    bindgen="$root/target/wasm-tools/bin/wasm-bindgen"
  fi
fi
[ -x "$bindgen" ] || { echo "bench-wasm: no wasm-bindgen $version; run scripts/check-js.sh once, or set WASM_BINDGEN" >&2; exit 1; }
export WASM_BINDGEN="$bindgen"

package=packages/frasil
out="$root/target/bench-wasm"
mkdir -p "$out"
files=()
IFS=',' read -r -a list <<<"$levels"
for level in "${list[@]}"; do
  dist="$out/$level/dist"
  if [ "$build" = 1 ]; then
    echo "bench-wasm: building at opt-level $level"
    CARGO_PROFILE_WASM_RELEASE_OPT_LEVEL="$level" \
      CARGO_TARGET_DIR="$out/$level/target" \
      FRASIL_NPM_DIST="$dist" \
      node "$package/scripts/build.mjs"
    # The package's own package.json says its modules are ES modules; this copy needs one too,
    # or Node.js parses each module twice.
    printf '{ "type": "module" }\n' >"$out/$level/package.json"
  fi
  node "$package/bench/run.mjs" --dist "$dist" --label "$level" --runs "$runs" \
    --engines "$engines" --json "$out/$level/result.json" >/dev/null
  files+=("$out/$level/result.json")
done

node "$package/bench/run.mjs" --report "${files[@]}"
