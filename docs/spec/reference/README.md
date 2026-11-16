# Reference script

[`generate.py`](generate.py) generates the [test vectors](../vectors/README.md)
from the reference code in this directory. The code is written from the
specification and the standards it cites, independently of any
implementation. An implementation that reproduces the vectors byte for byte
agrees with the text; one that does not has found a fault in itself, in the
text or here.

## Modules

| Module | What it holds |
|---|---|
| [`primitives.py`](primitives.py) | HKDF, Ed25519 point arithmetic, strict verification and signing, the X25519 ladder, HChaCha20 and XChaCha20-Poly1305, HPKE base mode, each checked against its standard's own vectors |
| [`xwing.py`](xwing.py) | ML-KEM-768 (FIPS 203), X-Wing, and HPKE with X-Wing, written out and checked against the known answers in [`kats/xwing.json`](kats/xwing.json) |
| [`mldsa.py`](mldsa.py) | ML-DSA-65 (FIPS 204), written out and checked against Wycheproof's ML-DSA-65 vectors, a subset vendored in [`kats/mldsa65.json`](kats/mldsa65.json) |
| [`formats.py`](formats.py) | Deterministic CBOR, fixed example inputs, the identifier rule and the X-Wing key check |
| [`crypto.py`](crypto.py) | [crypto.md](../crypto.md): the label registry, key checks with Wycheproof, test fixtures |
| [`wraps.py`](wraps.py) | crypto.md's X-Wing wrap and its opening |
| [`history_sigs.py`](history_sigs.py) | crypto.md's keys commitment and device ID, keys by their hash, signature schemes 0 and 2, anchors and coverage |
| [`clocks.py`](clocks.py) | [overview.md](../overview.md)'s time: the timeline, the estimates, every timer, `check_expiry` and `check_policy`, and each timed rule as a decision from its inputs |
| [`events.py`](events.py) | [events.md](../events.md): the envelope, event IDs, per-device chains, causal order and fork evidence |
| [`identity.py`](identity.py) | [identity.md](../identity.md): device keys, device lists and their merge, passkeys, recovery keys and entries, fingerprints, pins; the recovery agent's vectors |
| [`roster.py`](roster.py) | [roster.md](../roster.md): space events, members, the resolution procedure, frontiers, checks across logs |
| [`list_checkpoints.py`](list_checkpoints.py) | identity.md's list checkpoints: validity, acks and votes, the world after one, a holder that forgot; a seeded model check (`python list_checkpoints.py N`) |
| [`skeleton_cuts.py`](skeleton_cuts.py) | peers.md's skeleton cuts and truncation: a cut's checks at a peer, its effect, the skeleton after it, a peer that truncated; a seeded model check (`python skeleton_cuts.py N`) |
| [`checkpoints.py`](checkpoints.py) | roster.md's checkpoints and events.md's cuts: validity, votes, the world after a checkpoint, a replica that forgot; a seeded model check (`python checkpoints.py N` runs N histories) |
| [`spaces.py`](spaces.py) | roster.md's descriptor, policy, grant graph and effective membership; units.md's stream IDs |
| [`keygraph.py`](keygraph.py) | [keys.md](../keys.md): rotation sets, derivations, bundles and wraps, links, notices, heals, cascades, sealed names |
| [`units.py`](units.py) | [units.md](../units.md): units, objects, compaction, stubs, head statements, sync messages, the space snapshot |
| [`handshakes.py`](handshakes.py) | [transport.md](../transport.md): the member and device-to-peer handshakes, framing, mailboxes, the local network |
| [`storage.py`](storage.py) | [peers.md](../peers.md): credentials and proofs, recovery entries, the administrator skeleton, stability, release and collection |
| [`admission.py`](admission.py) | [admission.md](../admission.md): the admission code and its exchange, the setup code, the welcome, top-ups, lookups |
| [`at_rest.py`](at_rest.py) | [at-rest.md](../at-rest.md): sealed device keys, the store's keys, records and restore detection |
| [`ext_invite_links.py`](ext_invite_links.py) | [ext-invite-links.md](../ext-invite-links.md) |
| [`guests.py`](guests.py) | [ext-guests.md](../ext-guests.md) |
| [`ext_restricted.py`](ext_restricted.py) | [ext-restricted-spaces.md](../ext-restricted-spaces.md) |
| [`ephemeral.py`](ephemeral.py) | [ext-ephemeral.md](../ext-ephemeral.md) |
| [`library.py`](library.py) | [ext-libraries.md](../ext-libraries.md), with the deposit grant's purpose 4 and key 7 where ext-deposit-tokens.md is implemented |
| [`voprf.py`](voprf.py) | RFC 9496's ristretto255 and RFC 9497's VOPRF, mode `modeVOPRF`, suite ristretto255-SHA512, checked against both RFCs' vectors in [`kats/ristretto255-voprf.json`](kats/ristretto255-voprf.json), the batch included |
| [`ext_deposit_tokens.py`](ext_deposit_tokens.py) | [ext-deposit-tokens.md](../ext-deposit-tokens.md): keys, the grant, tokens and messages; a device's key checks and consistency rule, requests and finishing; a peer's checks, issuance with the allowance window and space shares, redemption, the two budgets and key rotation, as state transitions |
| [`signed_request.py`](signed_request.py) | [ext-app-requests.md](../ext-app-requests.md) |
| [`ext_drive.py`](ext_drive.py) | [ext-drive.md](../ext-drive.md): the forms, reading a drive, shown names and each change, on a model of Loro's tree |
| [`ext_file_versions.py`](ext_file_versions.py) | [ext-file-versions.md](../ext-file-versions.md): supersessions, the supersession set a Blobs replica keeps, a compactor's pairs and their check, the peer's listings, heads, depth and retention, and the cadence |
| [`ext_next_endpoints.py`](ext_next_endpoints.py) | [ext-next-endpoints.md](../ext-next-endpoints.md): a rotation that takes the announced key, `NextEndpoint` and its receiver, and the tickets dialed when reconnecting |
| [`ext_space_files.py`](ext_space_files.py) | [ext-space-files.md](../ext-space-files.md): the records, the way in and its seal, files with each way in, appends and truncation, and the roads in |
| [`adapters.py`](adapters.py) | [adapter-loro.md](../adapter-loro.md), [adapter-records.md](../adapter-records.md) and [adapter-blobs.md](../adapter-blobs.md) |
| [`generate.py`](generate.py) | Runs every self-test, checks the label registry, and writes or checks every vector file, its long byte strings in `blobs` ([vectors README](../vectors/README.md#long-byte-strings)) |

The `cryptography` package provides Ed25519, X25519, ChaCha20-Poly1305 and an
HKDF to check against, and OpenSSL's ML-DSA through the same package as a
second check of `mldsa.py`. The standard library provides SHA-256 and HMAC.
Everything else is written here.

## Running it

Python 3.12 or later. The virtual environment lives in a git-ignored
directory here; nothing is installed outside it.

```sh
cd docs/spec/reference
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
.venv/bin/python generate.py --check   # exit 1 if any vector file differs
.venv/bin/python generate.py           # rewrite the vector files
```

Before writing anything, `generate.py` runs every module's self-test and
checks that no label in crypto.md's registry equals or prefixes another, and
that every label a module uses is registered. A full run takes a few minutes,
most of it ML-DSA-65 signing in pure Python.

The first run downloads Wycheproof's test files and licence from a pinned
commit into `.cache/` (git-ignored) and refuses them unless their SHA-256
matches; later runs work offline. With no network and no cache, the script
stops with `could not fetch <url>: <reason>` and exit status 1, so `--check`
fails rather than passing.

Every vector function is deterministic: the output does not depend on the
order of Python's sets or dicts, and `--check` passes under any value of
`PYTHONHASHSEED`.
