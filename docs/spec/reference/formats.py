"""Shared helpers, written from the specifications, independently of any implementation:
fixed example inputs, the identifier rule, the deterministic CBOR subset the
signed formats use, and the X-Wing key check of crypto.md, "X-Wing and
ML-DSA-65 public keys"."""

from __future__ import annotations

import unicodedata

import xwing

from primitives import SpecError, ed25519_public, sha256, x25519_valid

# The revision, 1 for protocol 1 (overview.md, "Version policy"): `Hello`,
# `PeerHello` and `Offer` carry it, and a store's head and a space file's manifest
# record it.
REVISION = 1


def identifier_ok(text: str) -> bool:
    """No control character (Unicode category Cc), and not only white space."""
    return not text.isspace() and not any(unicodedata.category(c) == "Cc" for c in text)


def example(name: str) -> bytes:
    """A fixed 32-byte input: SHA-256 of a description, so no value is magic."""
    return sha256(b"frasil spec example/" + name.encode())


class Key:
    """A key pair used in the examples: its name, identity seed and public
    key, and the X-Wing seed and key of a key that names one."""

    def __init__(self, name: str, seed: bytes, hybrid_seed: bytes | None = None):
        self.name = name
        self.seed = seed
        self.identity = ed25519_public(seed)
        self.hybrid_seed = hybrid_seed
        self.hybrid = None if hybrid_seed is None else xwing.xwing_public_key(hybrid_seed)


def device(name: str) -> Key:
    return Key(name, example(f"{name}/ed25519"))


# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 section 4.2.1), the subset signed logs use.

UNSIGNED, BYTES, TEXT, ARRAY, MAP = 0, 2, 3, 4, 5


def head(major: int, value: int) -> bytes:
    top = major << 5
    if value < 24:
        return bytes([top | value])
    if value <= 0xFF:
        return bytes([top | 24, value])
    if value <= 0xFFFF:
        return bytes([top | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([top | 26]) + value.to_bytes(4, "big")
    return bytes([top | 27]) + value.to_bytes(8, "big")


def cbor_bytes(value: bytes) -> bytes:
    return head(BYTES, len(value)) + value


def cbor_text(value: str) -> bytes:
    raw = value.encode()
    return head(TEXT, len(raw)) + raw


class Reader:
    def __init__(self, data: bytes):
        self.data = data

    def take(self, count: int) -> bytes:
        if len(self.data) < count:
            raise SpecError("Malformed")
        taken, self.data = self.data[:count], self.data[count:]
        return taken

    def head(self, major: int) -> int:
        initial = self.take(1)[0]
        if initial >> 5 != major:
            raise SpecError("Malformed")
        low = initial & 31
        if low < 24:
            return low
        sizes = {24: (1, 24), 25: (2, 0x100), 26: (4, 0x10000), 27: (8, 0x100000000)}
        if low not in sizes:
            raise SpecError("Malformed")
        size, minimum = sizes[low]
        value = int.from_bytes(self.take(size), "big")
        if value < minimum:
            raise SpecError("Malformed")
        return value

    def key(self, expected: int) -> None:
        if self.head(UNSIGNED) != expected:
            raise SpecError("Malformed")

    def bytes(self, length: int | None = None) -> bytes:
        value = self.take(self.head(BYTES))
        if length is not None and len(value) != length:
            raise SpecError("Malformed")
        return value

    def text(self, maximum: int) -> str:
        length = self.head(TEXT)
        if length == 0 or length > maximum:
            raise SpecError("Malformed")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise SpecError("Malformed") from error


def xwing_valid(key: bytes) -> bool:
    """crypto.md, xwing_valid: 1,216 bytes, an ML-KEM-768 encapsulation key
    whose coefficients are below 3,329, and a valid X25519 key."""
    return (
        len(key) == xwing.XWING_PK_SIZE
        and xwing.mlkem768_encapsulation_key_valid(key[: xwing.EK_SIZE])
        and x25519_valid(key[xwing.EK_SIZE :])
    )


hybrid_key_valid = xwing_valid


def u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")
