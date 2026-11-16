#!/usr/bin/env bash
# `cargo check` of the `frasil` library for the mobile targets applications
# build it for, with the native features they use: the default features
# (SQLite, iroh, the server binding and the built-in adapters), and the
# index on iOS, whose SQLCipher builds on CommonCrypto.
#
#   - iOS: aarch64-apple-ios and aarch64-apple-ios-sim, on macOS with Xcode;
#   - Android: aarch64-linux-android, with an Android NDK that
#     ANDROID_NDK_HOME, ANDROID_NDK_LATEST_HOME or ANDROID_NDK_ROOT names
#     (r26 or later; GitHub's hosted Ubuntu runners have one).
#
# Installs nothing: each target's standard library must be installed for the
# toolchain rust-toolchain.toml pins (`rustup target add <target>`).
#
#   scripts/check-mobile.sh            # iOS and Android
#   scripts/check-mobile.sh ios        # iOS only
#   scripts/check-mobile.sh android    # Android only
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() {
  echo "check-mobile: $*" >&2
  exit 1
}

which="${1:-all}"
case "$which" in
  all | ios | android) ;;
  *) fail "unknown platform '$which'; use ios, android or nothing" ;;
esac

sysroot="$(rustc --print sysroot)"
need_target() {
  [ -d "$sysroot/lib/rustlib/$1" ] ||
    fail "the Rust standard library for $1 is not installed; run: rustup target add $1"
}

check() {
  local target="$1"
  shift
  echo "check-mobile: frasil for $target ${*:-(default features)}"
  # shellcheck disable=SC2068 # each argument is one cargo argument
  cargo check --locked -p frasil --lib --target "$target" $@
}

ios() {
  [ "$(uname -s)" = "Darwin" ] || fail "iOS builds need macOS with Xcode"
  command -v xcrun >/dev/null || fail "xcrun is missing; install Xcode"
  for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    need_target "$target"
    check "$target"
    check "$target" --features index
  done
}

android() {
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_ROOT:-}}}"
  [ -n "$ndk" ] && [ -d "$ndk" ] ||
    fail "no Android NDK; set ANDROID_NDK_HOME to one (r26 or later)"
  local host
  case "$(uname -s)" in
    Darwin) host=darwin-x86_64 ;;
    Linux) host=linux-x86_64 ;;
    *) fail "Android builds need a macOS or Linux host" ;;
  esac
  local bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
  local api=24
  [ -x "$bin/aarch64-linux-android$api-clang" ] ||
    fail "no aarch64-linux-android$api-clang in $bin"
  local target=aarch64-linux-android
  need_target "$target"
  # The C code that build scripts compile (ring, SQLite) uses the NDK's
  # compiler and archiver.
  CC_aarch64_linux_android="$bin/aarch64-linux-android$api-clang" \
    AR_aarch64_linux_android="$bin/llvm-ar" \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin/aarch64-linux-android$api-clang" \
    check "$target"
}

case "$which" in
  ios) ios ;;
  android) android ;;
  all)
    ios
    android
    ;;
esac
echo "check-mobile: done"
