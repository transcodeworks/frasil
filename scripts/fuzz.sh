#!/usr/bin/env bash
# Run the fuzz targets with cargo-fuzz and libFuzzer, each for a given number
# of seconds, then print executions, coverage and corpus size per target.
# Exits non-zero if any target found a crash, an out-of-memory input or a
# timeout; the input is saved under <package>/artifacts/<target>/.
#
# Two packages hold the targets, each its own workspace: fuzz/ (the
# protocol crates and the developer crate) and apps/relay/fuzz/
# (frasil-relay's own records). Both build with --all-features, so the targets
# of every extension build and run.
#
# Installs nothing system-wide. cargo-fuzz must be the version pinned below:
# the one on the PATH if it is, otherwise one installed with `cargo install`
# into target/fuzz-tools and reused on later runs. It needs a nightly
# toolchain: rustup toolchain install nightly.
#
#   scripts/fuzz.sh                                every target for 60 seconds
#   scripts/fuzz.sh 600                            every target for 10 minutes
#   scripts/fuzz.sh 600 base_cbor relay_records    only these targets
#   scripts/fuzz.sh --jobs 7 600                   seven targets at a time
#   scripts/fuzz.sh --build-only                   build every target, run none
#   scripts/fuzz.sh --list                         list the targets
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo_fuzz_version=0.13.2
packages=(fuzz apps/relay/fuzz)
# The longest input libFuzzer tries. A hybrid signature alone takes 3,373
# bytes (Ed25519 and ML-DSA-65), so signed values need more than libFuzzer's
# default of 4,096.
max_len=16384
jobs=1
seconds=60
seconds_given=false
targets=()
list=false
build_only=false

fail() {
  echo "fuzz: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --jobs)
      [ $# -ge 2 ] || fail "--jobs needs a number"
      jobs="$2"
      shift 2
      ;;
    --list)
      list=true
      shift
      ;;
    --build-only)
      build_only=true
      shift
      ;;
    -h | --help)
      awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
      exit 0
      ;;
    -*) fail "unknown option $1 (try --help)" ;;
    *)
      # The first number is the duration; everything else names a target.
      if ! $seconds_given && [ ${#targets[@]} -eq 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
        seconds="$1"
        seconds_given=true
      else
        targets+=("$1")
      fi
      shift
      ;;
  esac
done
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || fail "--jobs needs a positive number, not $jobs"

command -v cargo >/dev/null || fail "cargo is not installed; see https://rustup.rs"
command -v rustup >/dev/null || fail "rustup is not installed; cargo-fuzz needs a nightly toolchain through rustup"
rustup run nightly rustc --version >/dev/null 2>&1 ||
  fail "no nightly toolchain; run: rustup toolchain install nightly"

# cargo-fuzz at the pinned version: the one on the PATH if it is, otherwise
# one installed into target/fuzz-tools.
fuzz_version() { "$1" --version 2>/dev/null | awk '{ print $2 }'; }
installed="$(command -v cargo-fuzz || true)"
if [ -z "$installed" ] || [ "$(fuzz_version "$installed")" != "$cargo_fuzz_version" ]; then
  tools="$root/target/fuzz-tools"
  if [ ! -x "$tools/bin/cargo-fuzz" ] || [ "$(fuzz_version "$tools/bin/cargo-fuzz")" != "$cargo_fuzz_version" ]; then
    echo "fuzz: installing cargo-fuzz $cargo_fuzz_version into target/fuzz-tools"
    cargo install --quiet --locked --force --root "$tools" cargo-fuzz --version "$cargo_fuzz_version" ||
      fail "could not install cargo-fuzz"
  fi
  export PATH="$tools/bin:$PATH"
fi
fuzz=(cargo +nightly fuzz)

# Every target, and beside it the package it is in. Target names are unique
# across the packages: the peer's begin with `relay_`.
available=()
homes=()
for package in "${packages[@]}"; do
  while IFS= read -r name; do
    available+=("$name")
    homes+=("$package")
  done < <("${fuzz[@]}" list --fuzz-dir "$package")
done
if $list; then
  printf '%s\n' "${available[@]}"
  exit 0
fi

home_of() {
  local index
  for index in "${!available[@]}"; do
    if [ "${available[$index]}" = "$1" ]; then
      echo "${homes[$index]}"
      return 0
    fi
  done
  return 1
}

if [ ${#targets[@]} -eq 0 ]; then
  targets=("${available[@]}")
fi
for target in "${targets[@]}"; do
  home_of "$target" >/dev/null || fail "no fuzz target $target (try --list)"
done

# Debug assertions and overflow checks stay on: an overflow is a crash, not a
# wrapped value. AddressSanitizer is on by default. Each package builds all
# its targets at once, with every feature, from its committed lockfile.
for package in "${packages[@]}"; do
  wanted=false
  for target in "${targets[@]}"; do
    [ "$(home_of "$target")" = "$package" ] && wanted=true
  done
  $wanted || continue
  echo "fuzz: building the targets in $package with nightly"
  mkdir -p "$package/work"
  log="$package/work/build.log"
  if ! cargo +nightly fetch --locked --manifest-path "$package/Cargo.toml" >"$log" 2>&1 ||
    ! "${fuzz[@]}" build --fuzz-dir "$package" --all-features --debug-assertions >>"$log" 2>&1; then
    cat "$log" >&2
    fail "could not build the targets in $package"
  fi
done
if $build_only; then
  echo "fuzz: built the targets of ${packages[*]}"
  exit 0
fi

run() {
  local target="$1"
  local package
  package="$(home_of "$target")"
  local work="$package/work/$target"
  local log="$package/work/$target.log"
  mkdir -p "$work" "$package/artifacts/$target"
  local corpora=("$work")
  [ -d "$package/corpus/$target" ] && corpora+=("$package/corpus/$target")
  # A memory limit per input and per allocation, and a time limit per input:
  # exceeding any of them is a finding, like a crash.
  local arguments=(
    "-max_total_time=$seconds"
    -rss_limit_mb=1024
    -malloc_limit_mb=128
    -timeout=10
    "-max_len=$max_len"
    -print_final_stats=1
  )
  if "${fuzz[@]}" run --fuzz-dir "$package" --all-features --debug-assertions "$target" \
    "${corpora[@]}" -- "${arguments[@]}" >"$log" 2>&1; then
    echo ok >"$work.status"
  else
    echo failed >"$work.status"
  fi
}

summary() {
  local target="$1"
  local package
  package="$(home_of "$target")"
  local log="$package/work/$target.log"
  local status
  status="$(cat "$package/work/$target.status" 2>/dev/null || echo missing)"
  local last executions cov ft corpus new
  last="$(grep -E '^#[0-9]+' "$log" | tail -n 1 || true)"
  executions="$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | tail -n 1)"
  cov="$(sed -n 's/.* cov: \([0-9]*\).*/\1/p' <<<"$last")"
  ft="$(sed -n 's/.* ft: \([0-9]*\).*/\1/p' <<<"$last")"
  corpus="$(sed -n 's/.* corp: \([0-9]*\/[0-9]*[a-zA-Z]*\).*/\1/p' <<<"$last")"
  new="$(grep -E '^#[0-9]+[[:space:]]+NEW' "$log" | tail -n 1 | sed 's/^#\([0-9]*\).*/at #\1/' || true)"
  [ -n "$new" ] || new="before this run"
  if [ "$status" != ok ]; then
    local artifact
    artifact="$(sed -n 's/.*Test unit written to \(.*\)/\1/p' "$log" | tail -n 1)"
    printf '%-32s FAILED, see %s%s\n' "$target" "$log" "${artifact:+ and $artifact}"
  else
    printf '%-32s %12s execs  cov %6s  ft %7s  corpus %-14s  last new coverage %s\n' \
      "$target" "${executions:-?}" "${cov:-?}" "${ft:-?}" "${corpus:-?}" "$new"
  fi
  [ "$status" = ok ]
}

echo "fuzz: running ${#targets[@]} targets for ${seconds}s each, $jobs at a time"
index=0
while [ $index -lt ${#targets[@]} ]; do
  for target in "${targets[@]:$index:$jobs}"; do
    rm -f "$(home_of "$target")/work/$target.status"
    run "$target" &
  done
  wait
  index=$((index + jobs))
done

failed=0
for target in "${targets[@]}"; do
  summary "$target" || failed=1
done
exit $failed
