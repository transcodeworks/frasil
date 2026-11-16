# Releasing

Frasil releases everything together under one version: the crates on
crates.io, `@frasil/client` on npm, and the `frasil-relay` container image
on the GitHub Container Registry. The version is before 1.0, so a breaking
change raises the minor version.

## How a release happens

1. Pull requests merge into `main` with conventional titles
   ([CONTRIBUTING.md](CONTRIBUTING.md)).
2. `.github/workflows/release.yml` runs
   [release-please](https://github.com/googleapis/release-please) on every
   push to `main`. It keeps one release pull request open, `chore(main):
   release X.Y.Z`, which sets the version in every `Cargo.toml`, the three
   lockfiles and `packages/frasil/package.json`
   (`release-please-config.json`), and adds the release's notes to
   `CHANGELOG.md`.
3. Merging that pull request tags `vX.Y.Z`, writes the GitHub release, and
   publishes:
   - every crate that is not `publish = false`, in dependency order;
   - `@frasil/client`, with npm provenance;
   - the image's `X.Y.Z`, `X.Y`, `X` (from 1.0) and `latest` tags
     (`.github/workflows/docker.yml`). Every push to `main` also publishes
     `edge` and `sha-<commit>`. The image is the same for every operator:
     every extension is built in, and each deployment turns on its own
     with `FRASIL_EXTENSIONS` ([docs/self-hosting.md](docs/self-hosting.md)).

The protocol crates (`frasil-*`) are published because `frasil` and
`frasil-relay` depend on them. Their descriptions say they are internal
building blocks. `frasil-testkit`, `frasil-wasm`, `frasil-uniffi`, `frasil-tauri`,
`frasil-conformance` and the fuzz packages are `publish = false`.

A change that is incompatible on the wire is a new protocol number as well as
a breaking version.

No workflow stores a registry token: crates.io and npm both trust this
repository's `release.yml` through OpenID Connect. If a crates.io publish
stops part way, rerunning the job skips the crates already in the index at
the release's version.
