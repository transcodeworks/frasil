# Frasil protocol 1

Frasil is an end-to-end encrypted framework for collaboration without a
central authority. Each device keeps its own replica of shared data, and
devices exchange sealed, signed events, through always-on peers, directly
over a local network, or both, until every replica agrees. Membership is a
branching roster that every replica resolves by the same rules, with no
orderer and no clock; keys form a graph of states that every replica
derives alike; and a peer stores and relays what it cannot read. Frasil
decides who is trusted, how keys are managed, who may read and write, and
how changes travel. The application decides what its data means.

## Status

Specification of protocol 1. An incompatible change is a new protocol
number ([overview.md](overview.md), section 5.6). The implementation is
under active development and not yet recommended for production use.
`Hello`, `PeerHello` and `Offer`, a device's store and a space file carry a
revision number, which is 1 for protocol 1, and each end accepts only its
own ([overview.md](overview.md), section 5.6).

## Reading order

1. [overview.md](overview.md): the system model, the threat model, what
   each party sees, the conventions, time and the glossary. Every other
   document assumes it.
2. [crypto.md](crypto.md), then [events.md](events.md): the primitives,
   the device ID that names every device and the labels, then the envelope
   every signed thing shares.
3. [identity.md](identity.md), [roster.md](roster.md) and
   [keys.md](keys.md): who a person is, who is in a space, and how keys
   reach them. Read them together; each uses the others' results.
4. [units.md](units.md), [transport.md](transport.md) and
   [peers.md](peers.md): data, connections and always-on peers.
5. [admission.md](admission.md) and [at-rest.md](at-rest.md).
6. The extensions and adapters an implementation needs, each after the
   core documents it extends.

[rationale.md](rationale.md) explains the design and may be read at any
point after the overview.

## Documents

| Document | Specifies |
|---|---|
| **Front matter** | |
| [README.md](README.md) | This index, conformance, and how to run the vectors |
| [overview.md](overview.md) | Goals, the system model, the threat model, what each party sees, conventions, time, conformance, the glossary |
| [rationale.md](rationale.md) | Informative: why the design is as it is, and its known limits |
| [assumptions.md](assumptions.md) | Informative: what the protocol rests on (storage, randomness, primitives, time, the transport, the platform, peers, people, adapters and implementations), where the text relies on each, and what breaks if it does not hold |
| **Core** | |
| [crypto.md](crypto.md) | Primitives, a device's keys and device ID, key validation, X-Wing wraps, signature schemes 0 and 2, anchors and coverage, the label registry |
| [events.md](events.md) | The envelope, event IDs, per-device chains, causal and canonical order, heads, placement, fork evidence, limits |
| [identity.md](identity.md) | Device keys, the person ID, the device list and its merge, recovery keys, passkey members, possession proofs, fingerprints, pins, sealed list copies, account links |
| [roster.md](roster.md) | The genesis, members and levels, capabilities, labels, history modes, changes, authority, resolution, frontiers and the write rule, checks across logs, grants of spaces, `replace`, refused units, the invite hook |
| [keys.md](keys.md) | Key states, rotations, derivations, wraps, grant keys and space wraps, notices, links and gap keys, entitlement, heals, cascades, body keys, metadata and object keys, sealed names |
| [units.md](units.md) | Streams, units, objects, compaction and stubs, heads and statements, baseline sync, acknowledgements, the space snapshot, the adapter interface |
| [transport.md](transport.md) | Transport requirements, the member and device-to-peer handshakes, framing, mailboxes, the server and iroh bindings, local discovery |
| [peers.md](peers.md) | What a peer stores and checks, storage credentials, catch-up, release and restore, collection, the skeleton and twins, stability at the peer, erasure, quotas |
| [admission.md](admission.md) | The admission event and code, lookups, the setup code, the welcome, the newcomer's snapshot and top-ups, access requests |
| [at-rest.md](at-rest.md) | What a device stores and how it is sealed, sealed device keys, restore detection |
| **Extensions** | |
| [ext-invite-links.md](ext-invite-links.md) | Invite links, drops and claims; member type 3 and its successor |
| [ext-guests.md](ext-guests.md) | The guest preset, sessions, a guest's leave, nothing at rest, the bounded window and online-only |
| [ext-restricted-spaces.md](ext-restricted-spaces.md) | Restricted spaces and carve-outs |
| [ext-recovery-agent.md](ext-recovery-agent.md) | The recovery agent and its waiting period |
| [ext-ephemeral.md](ext-ephemeral.md) | The ephemeral channel |
| [ext-libraries.md](ext-libraries.md) | Libraries, tickets and usage at a peer, and holds of a file stored once per library |
| [ext-deposit-tokens.md](ext-deposit-tokens.md) | Deposit tokens: anonymous, single-use tokens that pay for device-mailbox deposits, drawn against a library's allowance on its issuer's grant or by a writer of one of its spaces |
| [ext-app-requests.md](ext-app-requests.md) | Device-signed requests to application servers |
| [ext-drive.md](ext-drive.md) | Drives: folders, files and documents of a space in one Loro document, their moves, trash and purge; a file's versions, heads and conflicts |
| [ext-space-files.md](ext-space-files.md) | Space files: one space in a file, verified as a peer's answers are, with a way in: rotation secrets, invite fragments or nothing, sealed or in the clear |
| [ext-next-endpoints.md](ext-next-endpoints.md) | Announced next endpoints: members with no always-on peer find each other again after their member endpoint keys rotate |
| [ext-file-versions.md](ext-file-versions.md) | File versions at a peer: the supersession a unit carries, and the retention by which a peer keeps a bounded number of a file's old versions and collects the rest |
| **Adapters** | |
| [adapter-loro.md](adapter-loro.md) | The Loro adapter: Loro documents, peer IDs bound to writers, suggestions |
| [adapter-records.md](adapter-records.md) | The Records adapter: tables of cells merged by logical stamps |
| [adapter-blobs.md](adapter-blobs.md) | The Blobs adapter: named entries, each naming an object, and references to another space's |

## Conformance

An implementation of **protocol 1 core** implements every core document
above. An extension or an adapter is optional. Each extension says which
core documents it extends, and what a core implementation that lacks it
does with what it defines: refuse it, ignore it, or hold it as
`ExtensionRequired`. An implementation that claims an extension or an
adapter also implements the core documents it builds on.

Each document's vector file covers its formats and procedures, and an
implementation of the document reproduces every vector in it, verdicts and
error classes included. [overview.md](overview.md), section 7, is the
normative statement of conformance.

## Conventions

[overview.md](overview.md) defines, once for every document: the
requirements language (BCP 14, section 5.1), notation (5.2), deterministic
CBOR (5.3), primitives and labels (5.4), error classes and their sorts
(5.5), the version policy (5.6), time and every timer (6), and the glossary
(8). Every label is listed in [crypto.md](crypto.md)'s registry, section
2.6. Each normative document has the same shape: overview, formats,
procedures, security considerations and test vectors.

## Reference script and vectors

The reference script in [`reference/`](reference/) generates every vector
file from the text of this specification, independently of any
implementation. It needs Python 3.12 or later, and installs only into a
virtual environment of its own:

```sh
cd docs/spec/reference
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
.venv/bin/python generate.py --check   # fails if any vector file differs
.venv/bin/python generate.py           # rewrites the vector files
```

`--check` compares the generated files with the committed ones byte for
byte. The first run fetches Wycheproof's test files from a pinned commit
and refuses them unless their SHA-256 matches; later runs work offline.
Running `--check` under two values of `PYTHONHASHSEED` confirms that the
output does not depend on Python's hash seed.

The vectors are in [`vectors/`](vectors/), one file per document, named
after it: `overview.json`, `crypto.json`, `events.json`, `identity.json`,
`roster.json`, `keys.json`, `units.json`, `transport.json`, `peers.json`,
`admission.json`, `at-rest.json`, and one per extension and adapter, such
as `ext-guests.json`, `ext-file-versions.json` and `adapter-loro.json`. Each document's last section
lists its file's families and what each shows. Each file keeps its long
byte strings once, in base64, and a reader expands them in place first, as
the [vectors README](vectors/README.md#long-byte-strings) describes. The
reference script's own [README](reference/README.md) describes its modules.

## Licence

This specification, its vectors and the reference script are part of the
Frasil repository and are licensed under its [MIT licence](../../LICENSE).
