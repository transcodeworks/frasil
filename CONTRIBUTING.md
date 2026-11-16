# Contributing to Frasil

Thank you for helping. Frasil is under active development.
Protocol 1 is the current protocol; an incompatible change to it is a new
protocol number, and extensions and clarifications to the specification are
as welcome as changes to the code.

- Questions, bugs and proposals: open an
  [issue](https://github.com/transcodeworks/frasil/issues/new/choose).
- Security vulnerabilities: never in public. See [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
  Report conduct concerns to
  [conduct@transcode.works](mailto:conduct@transcode.works).

[AGENTS.md](AGENTS.md) holds the repository's conventions in full: where
things live, the invariants of the code, and how dependencies are pinned.
Read it before a larger change.

## Build and test

You need the Rust toolchain that `rust-toolchain.toml` pins (rustup installs
it on first use), Node.js 24 (the version CI uses for development; the package itself
supports Node.js 20 and later), and for the browser package the pnpm version
in `package.json`'s `packageManager` field. These are the checks CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
node scripts/fetch-wycheproof.mjs            # once; frasil-crypto's Wycheproof test reads it
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo deny check
```

CI runs the tests with `cargo nextest run`, then the doctests with
`cargo test --doc`; plain `cargo test` covers both. Use `-p <crate>` while
you iterate.

By area:

- Features of `frasil`: `scripts/check-features.sh` (Clippy on no
  features, each alone, the defaults plus each, the browser set and every
  feature).
- Browser: `scripts/check-wasm.sh` (`frasil-wasm` on wasm32 in Node.js),
  `scripts/check-browser.sh` (`frasil`'s `browser` feature in headless
  Chromium, in a page and a worker),
  `scripts/check-js.sh` (the npm package in Chromium and WebKit), then
  `pnpm install --frozen-lockfile && pnpm lint`. WebKit runs by default, so
  install Playwright's browsers once with
  `pnpm --dir packages/frasil exec playwright install chromium webkit`
  (`npx playwright install webkit` from `packages/frasil` adds WebKit
  alone); `--engines chromium` limits a run to Chromium. Playwright's WebKit
  has no origin-private file system, so the index scenario skips it there.
- Fuzz targets: `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`, the
  same for `apps/relay/fuzz/Cargo.toml`, and `scripts/fuzz.sh --build-only`
  (nightly Rust and cargo-fuzz). See [docs/fuzzing.md](docs/fuzzing.md).
- Specification: from `docs/spec/reference`, in a venv with the pinned
  requirements (Python 3.12 or later),
  `python3 generate.py --check`.

Tests marked `#[ignore]` are measurements or need an S3-compatible service.

## Tooling

- **What CI runs.** A pull request runs only the jobs that build what it
  changes, so that a change to one area does not wait for every
  platform. `scripts/ci-areas.sh` maps each changed path to those jobs:
  documentation (`docs/` outside `docs/spec/`, Markdown and licence files)
  runs none of them; `docs/spec/` runs the vector check, and the vectors
  also run the Rust tests that read them; a crate runs every job that
  builds it; `packages/`, the pnpm files and the wasm crate run the
  package's job; a path it does not know, or any change to
  `.github/workflows/` or `scripts/`, runs everything. A push to `main`
  runs everything unless it changes documentation only.
  `scripts/ci-areas-test.sh` tests the mapping, and checks it against the
  dependencies between the crates; run it when you change either.
- **The required check.** `ci-ok` waits for every job and fails if one
  failed or was cancelled; a job skipped because the change does not
  affect it counts as passed. It is the one check a merge needs.
- **Package checks.** `pnpm --dir packages/frasil check:package` checks the
  packed npm package: its manifest with publint, and the types each entry
  resolves to with Are the Types Wrong, for an ESM-only package.
  `pnpm --dir packages/frasil knip` reports unused files, dependencies and
  exports. `scripts/check-js.sh` runs both, and the release checks the
  package again before it publishes.
- **Dependency updates.** Dependabot proposes Cargo, npm and GitHub Actions
  updates weekly, grouped, a week after their release
  (`.github/dependabot.yml`). The pins that move only by hand are listed
  there with their reasons. Review each update as a pin change.

## Changing the protocol

The specification in [`docs/spec/`](docs/spec/README.md) is normative and
uses the BCP 14 keywords (MUST, SHOULD, MAY). Code follows the text. A
change to protocol behaviour starts in the specification, and one pull
request carries all of it, in this order:

1. The text of the affected documents. New capabilities go in an extension
   (`ext-*.md`, a Cargo feature that is off by default) where they can.
2. The reasoning, in [`docs/spec/rationale.md`](docs/spec/rationale.md),
   which is informative.
3. The reference code in `docs/spec/reference/`.
4. The test vectors, regenerated with `generate.py`, never edited by hand.
   `generate.py --check` must pass.
5. The Rust code, and the claims in each crate's `claims.txt`.

If the text is wrong or ambiguous, fix the text rather than resolving it
silently in code. For a large change, open a proposal issue first.

## Pull requests

- Branch from `main` and open a pull request against it.
- Commit subjects and pull request titles use a conventional prefix with a
  scope, then a sentence about the behaviour, for example
  `fix(drive): a stale save stays a head and does not take the file's place`.
  Use `spec(...)` for specification changes, and `feat`, `fix`, `docs`,
  `test`, `chore` or `ci` otherwise.
- Keep one concern per pull request. Adding or bumping a dependency pin is
  a pull request of its own.
- When behaviour changes, update the matching guide in `docs/`, the crate
  docs, and `packages/frasil/README.md` for the browser surface.
- Source files carry no licence header.
- Releases are cut from these titles by release-please; see
  [RELEASING.md](RELEASING.md).

## Licence of contributions

Frasil is MIT ([LICENSE](LICENSE)). By contributing, you agree that your
contribution is licensed under the same MIT licence (inbound = outbound).
There is no contributor licence agreement to sign.
