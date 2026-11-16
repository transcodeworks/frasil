#!/usr/bin/env python3
"""Generate the test vectors in docs/spec/vectors/ from the reference code.

The reference code is written from the specifications and the standards they
cite, and shares no code with any implementation. It uses the `cryptography`
package for Ed25519, X25519, ChaCha20-Poly1305 and HKDF and the standard
library for SHA-256 and HMAC, and writes the rest itself: point validation,
HChaCha20, HPKE, ML-KEM-768, X-Wing, ML-DSA-65, ristretto255 and RFC 9497's
VOPRF, deterministic CBOR and every
Frasil format. An implementation that reproduces these vectors byte for byte
agrees with the text.

    python generate.py           # write the vector files
    python generate.py --check   # fail if a vector file differs

The key validation vectors run Wycheproof files, fetched once from a pinned
commit into `.cache/` and checked by SHA-256 (crypto.md).
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import re
import sys
from pathlib import Path

import mldsa
import xwing
from primitives import self_test

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent / "vectors"

# Every vector file, the module and function that produce it. One file per
# document of the specification.
OUTPUTS = [
    ("overview.json", "clocks", "overview_vectors"),
    ("crypto.json", "crypto", "crypto_vectors"),
    ("events.json", "events", "events_vectors"),
    ("identity.json", "identity", "identity_vectors"),
    ("roster.json", "roster", "roster_vectors"),
    ("keys.json", "keygraph", "keys_vectors"),
    ("units.json", "units", "units_vectors"),
    ("transport.json", "handshakes", "transport_vectors"),
    ("peers.json", "storage", "peers_vectors"),
    ("admission.json", "admission", "admission_vectors"),
    ("at-rest.json", "at_rest", "at_rest_vectors"),
    ("ext-invite-links.json", "ext_invite_links", "ext_invite_links_vectors"),
    ("ext-guests.json", "guests", "ext_guests_vectors"),
    ("ext-restricted-spaces.json", "ext_restricted", "ext_restricted_spaces_vectors"),
    ("ext-recovery-agent.json", "identity", "ext_recovery_agent_vectors"),
    ("ext-ephemeral.json", "ephemeral", "ext_ephemeral_vectors"),
    ("ext-libraries.json", "library", "ext_libraries_vectors"),
    ("ext-deposit-tokens.json", "ext_deposit_tokens", "ext_deposit_tokens_vectors"),
    ("ext-app-requests.json", "signed_request", "ext_app_requests_vectors"),
    ("ext-drive.json", "ext_drive", "ext_drive_vectors"),
    ("ext-space-files.json", "ext_space_files", "ext_space_files_vectors"),
    ("ext-file-versions.json", "ext_file_versions", "ext_file_versions_vectors"),
    ("ext-next-endpoints.json", "ext_next_endpoints", "ext_next_endpoints_vectors"),
    ("adapter-loro.json", "adapters", "adapter_loro_vectors"),
    ("adapter-records.json", "adapters", "adapter_records_vectors"),
    ("adapter-blobs.json", "adapters", "adapter_blobs_vectors"),
]

# Modules whose self-tests run before anything is generated.
MODULES = [
    "crypto", "events", "identity", "roster", "spaces", "keygraph", "clocks",
    "history_sigs", "units", "adapters", "storage", "library", "admission",
    "guests", "ephemeral", "handshakes", "signed_request", "at_rest",
    "ext_invite_links", "ext_restricted", "ext_drive", "ext_space_files",
    "ext_file_versions", "ext_next_endpoints", "voprf", "ext_deposit_tokens", "checkpoints",
    "list_checkpoints", "skeleton_cuts",
]


def check_labels(modules: dict) -> None:
    """crypto.md's registry: no label, purpose string or reserved string
    equals or prefixes another, and every label a module uses is in it."""
    crypto = modules["crypto"]
    clashes = crypto.check_registry()
    assert not clashes, clashes
    known = set(crypto.registry_labels()) | set(crypto.RESERVED)
    missing = sorted(
        f"{name}: {label.decode(errors='replace')}"
        for name, module in modules.items()
        for label in getattr(module, "NEW_LABELS", [])
        if label not in known
    )
    assert not missing, "labels outside crypto.md's registry: " + ", ".join(missing)


# A byte string this long or longer is written once, in the file's `blobs`.
BLOB_MIN_BYTES = 1024
HEX = re.compile(r"(?:[0-9a-f]{2})+")


def compact(document: dict) -> dict:
    """The file as written (../vectors/README.md, "Long byte strings"): each
    distinct byte string of at least BLOB_MIN_BYTES bytes moves to the
    top-level `blobs` list, base64 with padding, in order of first
    occurrence; `{"blob": n}` stands in each place it held."""
    assert "blobs" not in document
    blobs: list[str] = []
    index: dict[str, int] = {}

    def walk(value):
        if isinstance(value, dict):
            assert set(value) != {"blob"}, "an object that reads as a blob reference"
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, str) and len(value) >= 2 * BLOB_MIN_BYTES and HEX.fullmatch(value):
            if value not in index:
                index[value] = len(blobs)
                blobs.append(base64.b64encode(bytes.fromhex(value)).decode())
            return {"blob": index[value]}
        return value

    out = walk(document)
    if blobs:
        out["blobs"] = blobs
    return out


def expand(document: dict) -> dict:
    """The inverse of `compact`: what a reader of the files does first."""
    blobs = document.get("blobs", [])

    def walk(value):
        if isinstance(value, dict):
            if set(value) == {"blob"}:
                return base64.b64decode(blobs[value["blob"]], validate=True).hex()
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value

    return walk({key: item for key, item in document.items() if key != "blobs"})


def render(document: dict) -> str:
    written = compact(document)
    assert expand(written) == document
    return json.dumps(written, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="fail if the vector files differ from the output"
    )
    args = parser.parse_args()
    self_test()
    xwing.self_test()
    mldsa.self_test()
    modules = {name: importlib.import_module(name) for name in MODULES}
    for module in modules.values():
        module.self_test()
    check_labels(modules)
    outputs = {
        name: render(getattr(modules[module], function)())
        for name, module, function in OUTPUTS
    }
    stale = []
    for name, text in outputs.items():
        path = VECTORS / name
        if args.check:
            if not path.exists() or path.read_bytes() != text.encode():
                stale.append(name)
        else:
            path.write_bytes(text.encode())
    unknown = sorted(
        p.name for p in VECTORS.glob("*.json") if p.name not in outputs
    )
    if unknown:
        print("vector files no document names: " + ", ".join(unknown))
        return 1
    if stale:
        print("vector files differ from the reference output: " + ", ".join(stale))
        return 1
    print("checked" if args.check else "wrote", ", ".join(outputs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
