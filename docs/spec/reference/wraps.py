"""The X-Wing wrap (crypto.md, "The X-Wing wrap" and "Opening a wrap").

A wrap seals a plaintext to one X-Wing public key:

    0x01 || u16be(0x647a) || enc (1,120) || ciphertext (n + 16)

    (enc, ciphertext) = HPKE-Seal(recipient's X-Wing key, info, aad = "", plaintext)

`info` is the label of the wrap's use, then u16be(suite), then what the
using document binds. X-Wing is the only suite: DHKEM(X25519, HKDF-SHA256),
0x0020, and every other suite are refused as UnsupportedVersion. A wrap names
no recipient and carries no signature. keygraph.py's bundle and space wraps
use this layout; so do the other uses crypto.md lists.

`HYBRID_SEED_LABEL` is the fixture derivation of a test device's X-Wing seed
(crypto.md, "A device's keys").
"""

from __future__ import annotations

import xwing
from primitives import SpecError

VERSION = 0x01
SUITE_XWING = 0x647A
SUITE_X25519 = 0x0020  # DHKEM(X25519, HKDF-SHA256): refused
HEADER_BYTES = 1 + 2
ENC_BYTES = xwing.XWING_CT_SIZE  # 1120
TAG_BYTES = 16
MIN_BYTES = HEADER_BYTES + ENC_BYTES + TAG_BYTES  # 1139, an empty plaintext

HYBRID_SEED_LABEL = b"frasil/device-hybrid-seed/v1"


def u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


def wrap_info(label: bytes, binds: bytes) -> bytes:
    """A wrap's info: its use's label, the suite, then what the use binds."""
    return label + u16be(SUITE_XWING) + binds


def seal_wrap(recipient_xwing: bytes, info: bytes, plaintext: bytes, eseed: bytes) -> dict:
    """Seal `plaintext` to an X-Wing key, with X-Wing's 64 bytes of
    encapsulation randomness given (`eseed`)."""
    assert len(eseed) == 64
    enc, ciphertext = xwing.hpke_xwing_seal(recipient_xwing, info, b"", plaintext, eseed)
    return {"info": info, "enc": enc, "ciphertext": ciphertext,
            "wrap": bytes([VERSION]) + u16be(SUITE_XWING) + enc + ciphertext}


def length_ok(n: int, length) -> bool:
    """`length` is one length, a (minimum, maximum) range, or None for any
    length from an empty plaintext's up."""
    if length is None:
        return n >= MIN_BYTES
    if isinstance(length, tuple):
        return length[0] <= n <= length[1]
    return n == length


def read_wrap(wrap: bytes, length=None) -> dict:
    """open_wrap, steps 1 to 5: the layout, with no key."""
    if len(wrap) < 1:
        raise SpecError("Malformed")
    if wrap[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(wrap) < 3:
        raise SpecError("Malformed")
    if int.from_bytes(wrap[1:3], "big") != SUITE_XWING:
        raise SpecError("UnsupportedVersion")
    if not length_ok(len(wrap), length) or len(wrap) < MIN_BYTES:
        raise SpecError("Malformed")
    return {"enc": wrap[HEADER_BYTES:HEADER_BYTES + ENC_BYTES],
            "ciphertext": wrap[HEADER_BYTES + ENC_BYTES:]}


def open_wrap(wrap: bytes, seed: bytes, info: bytes, length=None) -> bytes:
    """crypto.md, open_wrap, in order. A wrap meant for another recipient,
    log or use fails at step 6 as Decrypt, like a damaged one."""
    parts = read_wrap(wrap, length)
    return xwing.hpke_xwing_open(seed, parts["enc"], info, b"", parts["ciphertext"])
