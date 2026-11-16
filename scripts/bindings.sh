#!/usr/bin/env bash
# Generate the Swift and Kotlin glue of the native bindings from
# crates/frasil-uniffi, with the generator built at the library's own UniFFI
# version, and check it: `swift test` on bindings/swift and `gradle test` on
# bindings/kotlin, against the debug library. Gradle needs a JDK 21.
#
#   scripts/bindings.sh            generate, then test
#   scripts/bindings.sh --check    generate into a scratch directory and fail
#                                  if the committed glue differs, then test
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

check=false
case "${1:-}" in
  --check) check=true ;;
  "") ;;
  -h | --help)
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "bindings: unknown argument $1 (try --help)" >&2
    exit 2
    ;;
esac

cargo build --locked -p frasil-uniffi --features bindgen
case "$(uname -s)" in
  Darwin) library=target/debug/libfrasil_uniffi.dylib ;;
  *) library=target/debug/libfrasil_uniffi.so ;;
esac
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
target/debug/frasil-uniffi-bindgen generate --library "$library" \
  --language swift --language kotlin \
  --config crates/frasil-uniffi/uniffi.toml --out-dir "$out" --no-format
python3 scripts/bindings_normalize.py "$out"

copy() {
  if $check; then
    if ! cmp -s "$1" "$2"; then
      echo "bindings: $2 differs from what the generator writes; run scripts/bindings.sh" >&2
      exit 1
    fi
  else
    mkdir -p "$(dirname "$2")"
    cp "$1" "$2"
  fi
}
copy "$out/Frasil.swift" bindings/swift/Sources/Frasil/Frasil.swift
copy "$out/FrasilFFI.h" bindings/swift/Sources/FrasilFFI/include/FrasilFFI.h
copy "$out/FrasilFFI.modulemap" bindings/swift/Sources/FrasilFFI/include/module.modulemap
copy "$out/frasil/frasil_uniffi.kt" bindings/kotlin/src/main/kotlin/frasil/frasil_uniffi.kt

swift test --package-path bindings/swift
gradle -p bindings/kotlin test --no-daemon --max-workers=2
