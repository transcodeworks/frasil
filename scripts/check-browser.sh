#!/usr/bin/env bash
# Run the `frasil` crate's browser tests (crates/frasil/tests/browser.rs in a
# page, browser_worker.rs in a dedicated worker) under wasm-bindgen-test, in
# headless Chromium: wasm-bindgen-test-runner serves each test module, and
# Playwright's Chromium, from the npm package's lockfile, opens the page and
# reads the results. A local relay serves the recovery reopen scenarios, and
# another, with ext-deposit-tokens on and the test issuer trusted, the
# deposit-token scenario (browser_deposit_tokens.rs).
#
# Installs nothing system-wide. wasm-bindgen-test-runner must be the version
# of wasm-bindgen in Cargo.lock: the one on the PATH if it is, otherwise one
# installed with `cargo install` into target/wasm-tools. Playwright's Chromium
# must be installed already (`pnpm exec playwright install chromium` in
# packages/frasil), as for scripts/check-js.sh.
#
#   scripts/check-browser.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail() {
  echo "check-browser: $*" >&2
  exit 1
}

target=wasm32-unknown-unknown
features="browser,adapter-loro,adapter-records,adapter-blobs"

command -v node >/dev/null || fail "Node.js is not installed"
sysroot="$(rustc --print sysroot)"
[ -d "$sysroot/lib/rustlib/$target" ] ||
  fail "the Rust standard library for $target is not installed; run: rustup target add $target"
[ -d packages/frasil/node_modules/@playwright/test ] ||
  fail "Playwright is not installed; run: pnpm install --frozen-lockfile"

# The test runner must match the wasm-bindgen the tests link exactly.
version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
[ -n "$version" ] || fail "no wasm-bindgen in Cargo.lock"
runner="$(command -v wasm-bindgen-test-runner || true)"
if [ -z "$runner" ] || [ "$("$runner" --version | awk '{ print $2 }')" != "$version" ]; then
  tools="$root/target/wasm-tools"
  runner="$tools/bin/wasm-bindgen-test-runner"
  if [ ! -x "$runner" ] || [ "$("$runner" --version | awk '{ print $2 }')" != "$version" ]; then
    echo "check-browser: installing wasm-bindgen-test-runner $version into target/wasm-tools"
    cargo install --quiet --locked --force --root "$tools" wasm-bindgen-cli --version "$version"
  fi
fi

echo "check-browser: starting a local recovery peer"
cargo build --locked -p frasil-relay
relay="${CARGO_TARGET_DIR:-$root/target}/debug/frasil-relay"
peer_data="$(mktemp -d)"
FRASIL_LISTEN=127.0.0.1:18787 FRASIL_ORIGIN=http://127.0.0.1:18787 FRASIL_IROH=off FRASIL_DATA_DIR="$peer_data" \
  FRASIL_EXTENSIONS=none FRASIL_HOSTING=open "$relay" >target/check-browser-peer.log 2>&1 &
peer_pid=$!
tokens_data="$(mktemp -d)"
# The issuer's key is the Ed25519 public key of the seed [0x1d; 32] that
# browser_deposit_tokens.rs signs grants with.
FRASIL_LISTEN=127.0.0.1:18788 FRASIL_ORIGIN=http://127.0.0.1:18788 FRASIL_IROH=off FRASIL_DATA_DIR="$tokens_data" \
  FRASIL_EXTENSIONS=libraries,deposit-tokens \
  FRASIL_LIBRARY_ISSUERS=e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa \
  "$relay" >target/check-browser-tokens-peer.log 2>&1 &
tokens_pid=$!
trap 'kill "$peer_pid" "$tokens_pid" 2>/dev/null || true; wait "$peer_pid" "$tokens_pid" 2>/dev/null || true; rm -rf "$peer_data" "$tokens_data"' EXIT
node -e '
(async () => {
  for (let i = 0; i < 100; i++) {
    try { await fetch("http://127.0.0.1:18787"); await fetch("http://127.0.0.1:18788"); return; } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  process.exit(1);
})();'
status=0
for test in browser browser_worker browser_deposit_tokens; do
  # A fresh port for each runner: the previous one's may not be free yet.
  port="$(node -e 'const s = require("net").createServer(); s.listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); });')"
  test_features="$features"
  [ "$test" = browser_deposit_tokens ] && test_features="$features,ext-deposit-tokens"
  echo "check-browser: building the $test tests for $target"
  # Cargo's messages go to a file and its own output to a log, shown if the
  # build fails.
  if ! cargo test --locked --target "$target" -p frasil --no-default-features \
    --features "$test_features" --test "$test" --no-run --message-format=json \
    >"$root/target/check-browser-$test.json" 2>"$root/target/check-browser-$test-build.log"; then
    cat "$root/target/check-browser-$test-build.log" >&2
    fail "the $test tests did not build"
  fi
  module="$(node -e '
      let found = "";
      for (const line of require("fs").readFileSync(process.argv[2], "utf8").split("\n")) {
        if (!line.startsWith("{")) continue;
        const message = JSON.parse(line);
        if (message.reason === "compiler-artifact" && message.executable &&
            message.target.name === process.argv[1]) found = message.executable;
      }
      process.stdout.write(found);
    ' "$test" "$root/target/check-browser-$test.json")"
  [ -n "$module" ] || fail "the $test test module did not build"

  echo "check-browser: running the $test tests in headless Chromium"
  NO_HEADLESS=1 WASM_BINDGEN_TEST_ADDRESS="127.0.0.1:$port" "$runner" "$module" \
    >"$root/target/check-browser-$test.log" 2>&1 &
  server=$!
  if ! (cd packages/frasil && node -e '
      const { chromium } = require("@playwright/test");
      (async () => {
        const url = process.argv[1];
        let up = false;
        for (let i = 0; i < 600 && !up; i += 1) {
          try { await fetch(url); up = true; } catch { await new Promise((r) => setTimeout(r, 100)); }
        }
        if (!up) throw new Error(`the test runner did not answer at ${url} within 60 s`);
        const browser = await chromium.launch();
        const page = await browser.newPage();
        await page.goto(url);
        const deadline = Date.now() + 180000;
        let text = "";
        while (Date.now() < deadline) {
          text = await page.evaluate(() => document.body.innerText);
          if (/test result: (ok|FAILED)/.test(text)) break;
          await new Promise((r) => setTimeout(r, 250));
        }
        await browser.close();
        console.log(text.trim());
        process.exit(/test result: ok/.test(text) ? 0 : 1);
      })().catch((error) => { console.error(error); process.exit(1); });
    ' "http://127.0.0.1:$port"); then
    status=1
  fi
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
done
[ "$status" -eq 0 ] || fail "browser tests failed"
echo "check-browser: every browser test passed"
