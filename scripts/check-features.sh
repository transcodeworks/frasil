#!/usr/bin/env bash
# Run Clippy, with warnings denied, on the `frasil` library for the feature
# combinations an application might choose:
#
#   - no features;
#   - each feature alone;
#   - the default features;
#   - the default features plus each other feature;
#   - the built-in document adapters without a binding, on the host and on
#     wasm32-unknown-unknown, as a local cache over spaces uses them;
#   - the index on wasm32-unknown-unknown, alone and with the browser;
#   - the browser set, which frasil-wasm uses, on the host;
#   - every feature.
#
# The list of features comes from crates/frasil/Cargo.toml, so a new feature
# is checked without a change here. Every combination shares the workspace's
# target directory.
#
#   scripts/check-features.sh            # every combination
#   scripts/check-features.sh --list     # print the combinations only
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

manifest=crates/frasil/Cargo.toml

# The features table: each `name = [...]` line between `[features]` and the
# next table.
features_table() {
  sed -n '/^\[features\]/,/^\[/p' "$manifest" | grep -E '^[a-z0-9-]+ = ' | sed 's/ = .*//'
}

defaults="$(sed -n '/^\[features\]/,/^\[/p' "$manifest" | sed -n 's/^default = \[\(.*\)\]/\1/p' | tr -d '" ')"
[ -n "$defaults" ] || { echo "check-features: no default features in $manifest" >&2; exit 1; }

all=()
while IFS= read -r feature; do
  case "$feature" in
    default | p1-full) ;;
    *) all+=("$feature") ;;
  esac
done < <(features_table)

# The features frasil-wasm turns on.
browser="$(sed -n 's/^frasil = .*features = \[\(.*\)\] }$/\1/p' crates/frasil-wasm/Cargo.toml | tr -d '" ')"
[ -n "$browser" ] || { echo "check-features: no frasil features in crates/frasil-wasm/Cargo.toml" >&2; exit 1; }

combinations=("--no-default-features")
for feature in "${all[@]}"; do
  combinations+=("--no-default-features --features $feature")
done
combinations+=("")
for feature in "${all[@]}"; do
  case ",$defaults," in
    *",$feature,"*) ;;
    *) combinations+=("--features $feature") ;;
  esac
done
combinations+=("--no-default-features --features adapter-loro,adapter-records")
combinations+=("--no-default-features --features adapter-loro,adapter-records --target wasm32-unknown-unknown")
combinations+=("--no-default-features --features index --target wasm32-unknown-unknown")
combinations+=("--no-default-features --features browser,index-diesel --target wasm32-unknown-unknown")
combinations+=("--no-default-features --features $browser")
combinations+=("--all-features")

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "${combinations[@]}"
  exit 0
fi

failed=()
count=0
for combination in "${combinations[@]}"; do
  count=$((count + 1))
  echo "check-features: [$count/${#combinations[@]}] frasil ${combination:-(default features)}"
  # shellcheck disable=SC2086 # each combination is a list of arguments
  if ! cargo clippy --locked -p frasil --lib $combination -- -D warnings; then
    failed+=("${combination:-(default features)}")
  fi
done

if [ "${#failed[@]}" -gt 0 ]; then
  echo "check-features: these combinations failed:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "check-features: all ${#combinations[@]} combinations pass"
