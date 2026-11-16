#!/usr/bin/env bash
# Which of CI's jobs (.github/workflows/ci.yml) a change needs, from the
# paths it changes. Reads one path per line on stdin, relative to the
# repository's root, and prints one `<area>=true|false` line per area, the
# form GITHUB_OUTPUT takes. The areas are the jobs they gate:
#
#   spec       spec-vectors: the reference script regenerates the vectors
#   check      check, test and test-os: the Rust workspace's lints and
#              tests on Linux, and its tests on Windows and macOS after
#              a merge
#   deny       deny: cargo-deny, and packaging the published crates
#   mobile     mobile: `frasil` for iOS and Android
#   features   features: `frasil`'s feature combinations
#   fuzz       fuzz-build: the two fuzz workspaces
#   wasm       wasm: frasil-wasm and frasil-crypto on wasm32 in Node.js
#   js         js-package: the npm package, the browser feature, lint
#
# A path the table below does not know runs everything. So does any path
# under .github/workflows, .github/actions or scripts. Documentation (docs/
# outside docs/spec, Markdown files, licence files) runs nothing.
#
#   scripts/ci-areas.sh           the areas the paths need
#   scripts/ci-areas.sh --full    everything, unless every path is documentation
#   scripts/ci-areas.sh --all     everything, whatever the paths
#
# scripts/ci-areas-test.sh checks the table, and checks it against the
# dependencies between the workspace's crates.
set -euo pipefail

areas="spec check deny mobile features fuzz wasm js"
rust="check deny mobile features fuzz wasm js"

mode=paths
case "${1:-}" in
  "") ;;
  --full) mode=full ;;
  --all) mode=all ;;
  -h | --help)
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "ci-areas: unknown argument $1 (try --help)" >&2
    exit 2
    ;;
esac

# The areas one path needs: a list of areas, `all`, or nothing.
areas_of() {
  case "$1" in
    # The workflows and the scripts they run.
    .github/workflows/* | .github/actions/* | scripts/*) echo all ;;
    # The Rust tests read the vectors (frasil-testkit, frasil-wasm's
    # vector tests, frasil-crypto's Wycheproof pins).
    docs/spec/vectors/*) echo spec check wasm ;;
    docs/spec/*) echo spec ;;
    # Documentation. No Rust source includes a Markdown file; the self-test
    # fails if one starts to.
    docs/* | *.md | LICENSE | LICENSE.* | LICENCE | LICENCE.* | */LICENSE | */LICENSE.* | */LICENCE | */LICENCE.*) ;;
    # Issue and pull request templates, dependency updates; the image has
    # its own workflow (docker.yml); release-please's own files.
    .github/*) ;;
    packaging/*) ;;
    release-please-config.json | .release-please-manifest.json) ;;
    .gitignore) ;;
    deny.toml) echo deny ;;
    Cargo.toml | Cargo.lock | rust-toolchain | rust-toolchain.toml | .cargo/*) echo "$rust" ;;
    # nextest's settings.
    .config/*) echo check ;;
    # Crates that some jobs do not build (checked against `cargo metadata`
    # by the self-test): the UniFFI bindings only in the workspace; the
    # testkit and the wasm crate, which neither `frasil` nor the fuzz
    # targets depend on.
    crates/frasil-uniffi/*) echo check deny ;;
    crates/frasil-testkit/* | crates/frasil-wasm/*) echo check deny wasm js ;;
    crates/*) echo "$rust" ;;
    apps/relay/fuzz/*) echo fuzz ;;
    # The peer: its fuzz targets include its sources, and the package's
    # scenarios and the browser tests run against it.
    apps/*) echo check deny fuzz js ;;
    tests/*) echo check deny ;;
    fuzz/*) echo fuzz ;;
    # No job builds the bindings; the workspace check is the closest.
    bindings/*) echo check ;;
    packages/* | package.json | pnpm-lock.yaml | pnpm-workspace.yaml | biome.json | biome.jsonc | .npmrc | .nvmrc | .node-version) echo js ;;
    *) echo all ;;
  esac
}

needed=" "
any=false
[ "$mode" = all ] || while IFS= read -r path || [ -n "$path" ]; do
  path="${path#./}"
  [ -n "$path" ] || continue
  these="$(areas_of "$path")"
  [ -n "$these" ] || continue
  any=true
  if [ "$these" = all ]; then
    needed=" $areas "
  else
    for area in $these; do
      case "$needed" in *" $area "*) ;; *) needed="$needed$area " ;; esac
    done
  fi
done

if [ "$mode" = all ] || { [ "$mode" = full ] && [ "$any" = true ]; }; then
  needed=" $areas "
fi

for area in $areas; do
  case "$needed" in
    *" $area "*) echo "$area=true" ;;
    *) echo "$area=false" ;;
  esac
done
