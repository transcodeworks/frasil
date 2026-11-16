# Test vectors

One JSON file per document of the specification, named after it.
[`../reference/generate.py`](../reference/generate.py) writes them all from the
reference code; `generate.py --check` confirms that the committed files are
exactly what it produces. Do not edit them by hand.

Each document's last section, "Test vectors", lists its file's families and
what each one shows. Values given byte for byte (encodings, keys, derived
secrets, signatures, wraps) must be reproduced exactly. Verdicts (valid, void,
pending, held, refused, and every error class) must be reached for the same
inputs, in the order the document's procedures check them.

| File | Document |
|---|---|
| [`overview.json`](overview.json) | [overview.md](../overview.md) |
| [`crypto.json`](crypto.json) | [crypto.md](../crypto.md) |
| [`events.json`](events.json) | [events.md](../events.md) |
| [`identity.json`](identity.json) | [identity.md](../identity.md) |
| [`roster.json`](roster.json) | [roster.md](../roster.md) |
| [`keys.json`](keys.json) | [keys.md](../keys.md) |
| [`units.json`](units.json) | [units.md](../units.md) |
| [`transport.json`](transport.json) | [transport.md](../transport.md) |
| [`peers.json`](peers.json) | [peers.md](../peers.md) |
| [`admission.json`](admission.json) | [admission.md](../admission.md) |
| [`at-rest.json`](at-rest.json) | [at-rest.md](../at-rest.md) |
| [`ext-invite-links.json`](ext-invite-links.json) | [ext-invite-links.md](../ext-invite-links.md) |
| [`ext-guests.json`](ext-guests.json) | [ext-guests.md](../ext-guests.md) |
| [`ext-restricted-spaces.json`](ext-restricted-spaces.json) | [ext-restricted-spaces.md](../ext-restricted-spaces.md) |
| [`ext-recovery-agent.json`](ext-recovery-agent.json) | [ext-recovery-agent.md](../ext-recovery-agent.md) |
| [`ext-ephemeral.json`](ext-ephemeral.json) | [ext-ephemeral.md](../ext-ephemeral.md) |
| [`ext-libraries.json`](ext-libraries.json) | [ext-libraries.md](../ext-libraries.md) |
| [`ext-deposit-tokens.json`](ext-deposit-tokens.json) | [ext-deposit-tokens.md](../ext-deposit-tokens.md) |
| [`ext-app-requests.json`](ext-app-requests.json) | [ext-app-requests.md](../ext-app-requests.md) |
| [`ext-drive.json`](ext-drive.json) | [ext-drive.md](../ext-drive.md) |
| [`ext-space-files.json`](ext-space-files.json) | [ext-space-files.md](../ext-space-files.md) |
| [`ext-file-versions.json`](ext-file-versions.json) | [ext-file-versions.md](../ext-file-versions.md) |
| [`ext-next-endpoints.json`](ext-next-endpoints.json) | [ext-next-endpoints.md](../ext-next-endpoints.md) |
| [`adapter-loro.json`](adapter-loro.json) | [adapter-loro.md](../adapter-loro.md) |
| [`adapter-records.json`](adapter-records.json) | [adapter-records.md](../adapter-records.md) |
| [`adapter-blobs.json`](adapter-blobs.json) | [adapter-blobs.md](../adapter-blobs.md) |

Byte strings are lowercase hex. Every signature is at full size; most of the
files' bulk is ML-DSA-65 signatures, ML-DSA-65 and X-Wing keys, and the events
that carry them.

## Long byte strings

A byte string of 1,024 bytes or more is written once per file, in base64
with padding (RFC 4648, section 4), as an entry of the top-level list
`blobs`. In each place it stands, the file holds the object `{"blob": n}`,
`n` the entry's index from 0. A reader first expands the file: it removes
`blobs` and replaces every object whose only key is `blob` by the lowercase
hex of entry `n`. The families are the expanded file; `blobs` is not one of
them, and no family holds an object whose only key is `blob`. Entries are in
the order of their first place in the file. A file without long byte strings
has no `blobs`.
