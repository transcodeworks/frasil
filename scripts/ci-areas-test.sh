#!/usr/bin/env bash
# Tests scripts/ci-areas.sh:
#
# 1. a table of paths and the areas each needs, and how lists of paths and
#    the --full and --all modes combine them;
# 2. that no Rust source includes a Markdown file, which ci-areas.sh treats
#    as documentation;
# 3. with Cargo, that each crate of the workspace needs every job that
#    builds it: `cargo metadata --no-deps` gives the dependencies between
#    the workspace's crates and the fuzz workspaces' path dependencies, and
#    each job's crates are those its roots reach. Without Cargo this part
#    is skipped, unless CI is set.
#
#   scripts/ci-areas-test.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
areas_sh="$root/scripts/ci-areas.sh"

failures=0
fail() {
  echo "ci-areas-test: FAIL: $*" >&2
  failures=$((failures + 1))
}

# The areas the script sets to true, space-separated, or `none`.
run() {
  local out
  out="$("$areas_sh" "$@" | sed -n 's/=true$//p' | tr '\n' ' ')"
  out="${out% }"
  echo "${out:-none}"
}

all="spec check deny mobile features fuzz wasm js"
rust="check deny mobile features fuzz wasm js"

# 1. path | the areas it needs, in the script's order
while IFS='|' read -r path expected; do
  [ -n "$path" ] || continue
  expected="${expected/@all/$all}"
  expected="${expected/@rust/$rust}"
  got="$(printf '%s\n' "$path" | run)"
  [ "$got" = "$expected" ] || fail "$path: expected '$expected', got '$got'"
done <<'TABLE'
README.md|none
CONTRIBUTING.md|none
docs/guide.md|none
docs/images/flow.svg|none
crates/frasil/README.md|none
LICENSE|none
packages/frasil/LICENSE|none
.github/ISSUE_TEMPLATE/bug.yml|none
.github/pull_request_template.md|none
.github/dependabot.yml|none
packaging/server/Dockerfile|none
release-please-config.json|none
.release-please-manifest.json|none
.gitignore|none
docs/spec/README.md|spec
docs/spec/crypto.md|spec
docs/spec/reference/generate.py|spec
docs/spec/reference/requirements.txt|spec
docs/spec/vectors/crypto.json|spec check wasm
.github/workflows/ci.yml|@all
.github/workflows/docs.yml|@all
.github/actions/setup/action.yml|@all
scripts/ci-areas.sh|@all
scripts/README.md|@all
deny.toml|deny
Cargo.toml|@rust
Cargo.lock|@rust
rust-toolchain.toml|@rust
.cargo/config.toml|@rust
.config/nextest.toml|check
crates/frasil/src/lib.rs|@rust
crates/frasil/Cargo.toml|@rust
crates/frasil-crypto/tests/wycheproof.rs|@rust
crates/frasil-store/src/lib.rs|@rust
crates/frasil-uniffi/src/lib.rs|check deny
crates/frasil-testkit/src/lib.rs|check deny wasm js
crates/frasil-wasm/src/lib.rs|check deny wasm js
crates/frasil-wasm/Cargo.toml|check deny wasm js
crates/frasil-new/src/lib.rs|@rust
apps/relay/src/main.rs|check deny fuzz js
apps/relay/Cargo.toml|check deny fuzz js
apps/relay/fuzz/fuzz_targets/relay_records.rs|fuzz
apps/relay/fuzz/Cargo.lock|fuzz
apps/other/src/main.rs|check deny fuzz js
tests/conformance/tests/sync.rs|check deny
fuzz/fuzz_targets/base_cbor.rs|fuzz
fuzz/Cargo.lock|fuzz
bindings/swift/Sources/Frasil/Frasil.swift|check
bindings/tauri/Cargo.toml|check
packages/frasil/src/index.ts|js
packages/frasil/package.json|js
package.json|js
pnpm-lock.yaml|js
pnpm-workspace.yaml|js
biome.json|js
.gitattributes|@all
Makefile|@all
something/new.txt|@all
TABLE

# Lists of paths, and the modes.
check_list() {
  local name="$1" expected="$2" got
  shift 2
  got="$(run "$@")"
  [ "$got" = "$expected" ] || fail "$name: expected '$expected', got '$got'"
}
check_list "no paths" none </dev/null
check_list "blank lines" none <<<$'\n\n'
check_list "docs only" none <<<$'README.md\ndocs/a.md\nLICENSE'
check_list "docs and the package" js <<<$'README.md\npackages/frasil/src/a.ts'
check_list "the package and the wasm crate" "check deny wasm js" <<<$'packages/frasil/src/a.ts\ncrates/frasil-wasm/src/lib.rs'
check_list "spec text and vectors" "spec check wasm" <<<$'docs/spec/crypto.md\ndocs/spec/vectors/crypto.json'
check_list "a leading ./" js <<<'./packages/frasil/src/a.ts'
check_list "a workflow among docs" "$all" <<<$'README.md\n.github/workflows/ci.yml'
check_list "--full, docs only" none --full <<<$'README.md\ndocs/a.md'
check_list "--full, no paths" none --full </dev/null
check_list "--full, one package file" "$all" --full <<<$'README.md\npackages/frasil/src/a.ts'
check_list "--full, the image only" none --full <<<'packaging/server/Dockerfile'
check_list "--all" "$all" --all </dev/null
if "$areas_sh" --bogus </dev/null >/dev/null 2>&1; then fail "an unknown argument is refused"; fi

# 2. No Rust source includes a Markdown file.
if included="$(grep -rnE --include='*.rs' 'include_(str|bytes)!\([^)]*\.md"' crates apps tests fuzz bindings 2>/dev/null)"; then
  fail "a Rust source includes a Markdown file, which ci-areas.sh treats as documentation:"
  echo "$included" >&2
fi

# 3. Each crate needs every job that builds it.
if command -v cargo >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  meta="$(mktemp -d)"
  trap 'rm -rf "$meta"' EXIT
  cargo metadata --no-deps --format-version 1 >"$meta/workspace.json"
  cargo metadata --no-deps --format-version 1 --manifest-path fuzz/Cargo.toml >"$meta/fuzz.json"
  cargo metadata --no-deps --format-version 1 --manifest-path apps/relay/fuzz/Cargo.toml >"$meta/relay-fuzz.json"
  # One line per crate: its directory, then the jobs that build it.
  python3 -I - "$root" "$meta" >"$meta/jobs.txt" <<'PY'
import json, os, sys

root, meta = sys.argv[1], sys.argv[2]
load = lambda name: json.load(open(os.path.join(meta, name)))
workspace = load("workspace.json")
members = {p["name"]: p for p in workspace["packages"] if p["source"] is None}
dirs = {name: os.path.relpath(os.path.dirname(p["manifest_path"]), root) for name, p in members.items()}

def reach(roots, dev):
    """The members `roots` depend on: normal and build dependencies, and the
    roots' own dev-dependencies when their tests are built."""
    seen, stack = set(), list(roots)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        for dep in members[name]["dependencies"]:
            if dep.get("path") is None or dep["name"] not in members:
                continue
            if dep["kind"] is None or dep["kind"] == "build" or (dev and name in roots):
                stack.append(dep["name"])
    return seen

def fuzz_roots(name):
    roots = set()
    for package in load(name)["packages"]:
        for dep in package["dependencies"]:
            if dep.get("path") and dep["name"] in members:
                roots.add(dep["name"])
    return roots

jobs = {
    "check": set(members),
    "deny": set(members),
    # scripts/check-mobile.sh, scripts/check-features.sh: `frasil`'s library.
    "mobile": reach({"frasil"}, dev=False),
    "features": reach({"frasil"}, dev=False),
    # scripts/check-wasm.sh: the tests of frasil-wasm and frasil-crypto.
    "wasm": reach({"frasil-wasm", "frasil-crypto"}, dev=True),
    # scripts/check-js.sh builds frasil-wasm and runs the scenarios against
    # frasil-relay; scripts/check-browser.sh runs `frasil`'s tests.
    "js": reach({"frasil-wasm", "frasil-relay"}, dev=False) | reach({"frasil"}, dev=True),
    "fuzz": reach(fuzz_roots("fuzz.json") | fuzz_roots("relay-fuzz.json"), dev=False),
}
for name in sorted(members):
    print(dirs[name], " ".join(job for job, crates in jobs.items() if name in crates))
PY
  while read -r dir needed; do
    case "$dir" in
      crates/* | apps/* | tests/*) ;;
      *) fail "workspace member $dir is outside crates/, apps/ and tests/, which ci-areas.sh knows" ;;
    esac
    got=" $(printf '%s\n' "$dir/src/lib.rs" "$dir/Cargo.toml" | run) "
    for job in $needed; do
      case "$got" in
        *" $job "*) ;;
        *) fail "$dir is built by the $job job, but a change to it does not run $job" ;;
      esac
    done
  done <"$meta/jobs.txt"
  echo "ci-areas-test: checked $(wc -l <"$meta/jobs.txt" | tr -d ' ') crates against cargo metadata"
elif [ -n "${CI:-}" ]; then
  fail "cargo or python3 is missing, so the crates were not checked"
else
  echo "ci-areas-test: cargo or python3 is missing; the crates were not checked"
fi

if [ "$failures" -gt 0 ]; then
  echo "ci-areas-test: $failures failed" >&2
  exit 1
fi
echo "ci-areas-test: passed"
