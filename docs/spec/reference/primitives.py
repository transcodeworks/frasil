"""Primitives for the reference script, written from their standards.

Nothing here comes from any implementation. Where the `cryptography` package
offers a primitive, it is used or cross-checked against; where it does not
(HChaCha20, HPKE with fixed ephemeral keys, point validation), the code
follows the cited text and is checked against that text's test vectors in
`self_test`.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SpecError(Exception):
    """An input a specification says to reject, with its error class."""

    def __init__(self, error: str):
        super().__init__(error)
        self.error = error


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def field(value: bytes) -> bytes:
    """Frasil's length-prefixed field: a big-endian u32 length, then the bytes."""
    return len(value).to_bytes(4, "big") + value


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869), with hmac, checked against `cryptography`.


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    ours = hkdf_expand(hkdf_extract(salt, ikm), info, length)
    theirs = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)
    assert ours == theirs, "HKDF disagrees with the cryptography package"
    return ours


# ---------------------------------------------------------------------------
# Edwards25519 (RFC 8032 section 5.1), for key validation.

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
L = 2**252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def point_add(a: tuple, b: tuple) -> tuple:
    """RFC 8032 section 5.1.4, extended homogeneous coordinates."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(k: int, point: tuple) -> tuple:
    result = IDENTITY
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def point_equal(a: tuple, b: tuple) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def point_encode(point: tuple) -> bytes:
    zi = _inv(point[2])
    x, y = point[0] * zi % P, point[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def point_decode(encoded: bytes) -> tuple | None:
    """RFC 8032 section 5.1.3, exactly: None where decoding fails."""
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P == 0:
        pass
    elif (v * x * x + u) % P == 0:
        x = x * SQRT_M1 % P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def point_decode_lenient(encoded: bytes) -> tuple | None:
    """A lenient decoding an implementation may use: y taken modulo p, and
    the sign bit applied even when x is 0. Used only to show which encodings
    such a decoder accepts and the specification refuses."""
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y = (y & ((1 << 255) - 1)) % P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P == 0:
        pass
    elif (v * x * x + u) % P == 0:
        x = x * SQRT_M1 % P
    else:
        return None
    if x & 1 != sign:
        x = (P - x) % P
    return (x, y, 1, x * y % P)


BASE = point_decode(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


def ed25519_checks(encoded: bytes) -> dict:
    """Every step of crypto.md, recorded."""
    point = point_decode(encoded) if len(encoded) == 32 else None
    result = {
        "length_ok": len(encoded) == 32,
        "decodes": point is not None,
        "canonical": point is not None and point_encode(point) == encoded,
        "small_order": None,
        "torsion_free": None,
    }
    if point is not None:
        result["small_order"] = point_equal(point_mul(8, point), IDENTITY)
        result["torsion_free"] = point_equal(point_mul(L, point), IDENTITY)
    return result


def ed25519_valid(encoded: bytes) -> bool:
    r = ed25519_checks(encoded)
    return bool(r["decodes"] and r["canonical"] and not r["small_order"] and r["torsion_free"])


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Ed25519 signing written out (RFC 8032 section 5.1.6), with the nonce chosen
# by the caller, and strict verification (crypto.md, "Strict Ed25519 verification").


def ed25519_scalar(seed: bytes) -> int:
    """RFC 8032 section 5.1.5: the clamped secret scalar of a seed."""
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


def _challenge(r_bytes: bytes, public: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % L


def ed25519_sign_with_nonce(seed: bytes, message: bytes, r: int) -> bytes:
    """An Ed25519 signature whose nonce is `r` instead of RFC 8032's
    deterministic one. Any such signature verifies; the vectors use it to show
    that a proof is not unique and to build signatures with a small-order R."""
    a = ed25519_scalar(seed)
    public = point_encode(point_mul(a, BASE))
    r_bytes = point_encode(point_mul(r % L, BASE))
    s = (r + _challenge(r_bytes, public, message) * a) % L
    return r_bytes + s.to_bytes(32, "little")


def ed25519_sign_deterministic(seed: bytes, message: bytes) -> bytes:
    """RFC 8032 section 5.1.6, written out; checked against `cryptography` in
    `self_test`. Device list entries and possession proofs are signed with it."""
    digest = hashlib.sha512(seed).digest()
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % L
    return ed25519_sign_with_nonce(seed, message, r)


def _negate(point: tuple) -> tuple:
    x, y, z, t = point
    return ((-x) % P, y, z, (-t) % P)


def _small_order(point: tuple) -> bool:
    return point_equal(point_mul(8, point), IDENTITY)


def ed25519_verify_strict(public: bytes, message: bytes, signature: bytes) -> bool:
    """crypto.md, "Strict Ed25519 verification": RFC 8032 section 5.1.7 with the
    cofactorless equation, and refusing S >= L, an R or A that is not a
    canonical encoding, and an R or A of small order. This is what
    ed25519-dalek's `verify_strict` accepts, which Frasil uses for every
    device list and roster entry signature and every proof."""
    if len(public) != 32 or len(signature) != 64:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    a_point = point_decode(public)
    r_point = point_decode(r_bytes)
    if a_point is None or r_point is None:
        return False
    if point_encode(a_point) != public or point_encode(r_point) != r_bytes:
        return False
    if _small_order(a_point) or _small_order(r_point):
        return False
    k = _challenge(r_bytes, public, message)
    check = point_add(point_mul(s, BASE), point_mul(k, _negate(a_point)))
    return point_encode(check) == r_bytes


def ed25519_verify_lenient(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 section 5.1.7 with the cofactorless equation, S < L, and no
    other refusal: R compared as bytes with the re-encoded point, A decoded
    as sent. Only to show which proofs a verifier that skips the strict
    checks would take."""
    if len(public) != 32 or len(signature) != 64:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    s = int.from_bytes(s_bytes, "little")
    a_point = point_decode(public)
    if s >= L or a_point is None:
        return False
    k = _challenge(r_bytes, public, message)
    check = point_add(point_mul(s, BASE), point_mul(k, _negate(a_point)))
    return point_encode(check) == r_bytes


def small_order_points() -> list[tuple]:
    """The eight points of order dividing 8, found by multiplying points by L."""
    y = 2
    while True:
        candidate = point_decode(y.to_bytes(32, "little"))
        y += 1
        if candidate is None:
            continue
        torsion = point_mul(L, candidate)
        if not point_equal(point_mul(4, torsion), IDENTITY):
            break
    points = []
    current = IDENTITY
    for _ in range(8):
        points.append(current)
        current = point_add(current, torsion)
    assert point_equal(current, IDENTITY)
    return points


# ---------------------------------------------------------------------------
# X25519 (RFC 7748 section 5), for key validation.

A24 = 121665
A = 486662


def x25519_clamp(secret: bytes) -> bytes:
    k = bytearray(secret)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def ladder(k: int, u: int, bits: int = 255) -> tuple[int, int]:
    """The Montgomery ladder of RFC 7748 section 5, returning projective
    (X : Z) of [k]P, with Z = 0 exactly when [k]P is the point at infinity.
    `u` must not be 0: the differential addition degenerates there."""
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(bits)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a_ = (x2 + z2) % P
        aa = a_ * a_ % P
        b_ = (x2 - z2) % P
        bb = b_ * b_ % P
        e = (aa - bb) % P
        c_ = (x3 + z3) % P
        d_ = (x3 - z3) % P
        da = d_ * a_ % P
        cb = c_ * b_ % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return x2, z2


def x25519_function(scalar: bytes, u_bytes: bytes) -> bytes:
    """X25519 as RFC 7748 section 5 defines it, for cross-checking."""
    k = int.from_bytes(x25519_clamp(scalar), "little")
    u = (int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)) % P
    if u == 0:
        return bytes(32)
    x, z = ladder(k, u)
    return (x * _inv(z) % P).to_bytes(32, "little")


def x25519_checks(encoded: bytes) -> dict:
    """Every step of crypto.md, recorded."""
    result = {
        "length_ok": len(encoded) == 32,
        "top_bit_clear": None,
        "below_p": None,
        "on_curve": None,
        "prime_order": None,
    }
    if len(encoded) != 32:
        return result
    raw = int.from_bytes(encoded, "little")
    result["top_bit_clear"] = raw >> 255 == 0
    u = raw & ((1 << 255) - 1)
    result["below_p"] = u < P
    u %= P
    rhs = (u * u * u + A * u * u + u) % P
    result["on_curve"] = rhs == 0 or pow(rhs, (P - 1) // 2, P) == 1
    if u == 0:
        result["prime_order"] = False
    else:
        _, z = ladder(L, u, bits=L.bit_length())
        result["prime_order"] = z == 0
    return result


def x25519_valid(encoded: bytes) -> bool:
    r = x25519_checks(encoded)
    return bool(r["length_ok"] and r["top_bit_clear"] and r["below_p"] and r["prime_order"])


def x25519_public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def x25519_shared(secret: bytes, public: bytes) -> bytes:
    """X25519 at use: refuses an all-zero result (RFC 9180 section 7.1.4)."""
    ours = x25519_function(secret, public)
    if ours == bytes(32):
        raise SpecError("Decrypt")
    theirs = X25519PrivateKey.from_private_bytes(secret).exchange(
        X25519PublicKey.from_public_bytes(public)
    )
    assert ours == theirs, "X25519 disagrees with the cryptography package"
    return ours


def small_order_u() -> list[int]:
    """Canonical u-coordinates of points of small order on the curve and its
    twist: those whose X25519 with any clamped scalar is 0."""
    found = {0}
    for point in small_order_points():
        zi = _inv(point[2])
        y = point[1] * zi % P
        if y != 1:
            found.add((1 + y) * _inv(1 - y) % P)
    # The twist's points of order 4 have u = 1 or u = -1; keep both (one is on
    # the curve, one on the twist) and check each is killed by the cofactor.
    found |= {1, P - 1}
    for u in found:
        if u:
            assert ladder(8, u)[1] == 0, u
    return sorted(found)


# ---------------------------------------------------------------------------
# ChaCha20, HChaCha20 and XChaCha20-Poly1305 (RFC 8439; draft-irtf-cfrg-xchacha-03).


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    words = lambda b: [int.from_bytes(b[i : i + 4], "little") for i in range(0, len(b), 4)]  # noqa: E731
    s = constants + words(key) + words(nonce16)
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return b"".join(w.to_bytes(4, "little") for w in s[0:4] + s[12:16])


def xchacha20poly1305_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    assert len(key) == 32 and len(nonce) == 24
    subkey = hchacha20(key, nonce[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\x00" * 4 + nonce[16:], plaintext, aad)


def xchacha20poly1305_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag

    subkey = hchacha20(key, nonce[:16])
    try:
        return ChaCha20Poly1305(subkey).decrypt(b"\x00" * 4 + nonce[16:], sealed, aad)
    except InvalidTag as error:
        raise SpecError("Decrypt") from error


# ---------------------------------------------------------------------------
# HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305
# (RFC 9180 sections 4.1, 5.1, 5.2), with a caller-chosen ephemeral key so
# that vectors are fixed.

KEM_SUITE = b"KEM" + (0x0020).to_bytes(2, "big")
HPKE_SUITE = b"HPKE" + (0x0020).to_bytes(2, "big") + (1).to_bytes(2, "big") + (3).to_bytes(2, "big")


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def _kem_shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    eae_prk = _labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return _labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", enc + pk_r, 32)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = _labeled_expand(HPKE_SUITE, secret, b"key", context, 32)
    nonce = _labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12)
    return key, nonce


def hpke_seal(
    pk_r: bytes, info: bytes, aad: bytes, plaintext: bytes, sk_e: bytes
) -> tuple[bytes, bytes]:
    """SetupBaseS then Seal with sequence number 0. Returns (enc, ciphertext)."""
    enc = x25519_public(sk_e)
    dh = x25519_shared(sk_e, pk_r)
    key, nonce = _key_schedule(_kem_shared_secret(dh, enc, pk_r), info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def hpke_open(sk_r: bytes, enc: bytes, info: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag

    dh = x25519_shared(sk_r, enc)
    key, nonce = _key_schedule(_kem_shared_secret(dh, enc, x25519_public(sk_r)), info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise SpecError("Decrypt") from error


# ---------------------------------------------------------------------------
# Self-tests against the standards' own vectors.


def self_test() -> None:
    # RFC 5869 Appendix A.1, test case 1.
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x0D))
    info = bytes(range(0xF0, 0xFA))
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = hkdf(salt, ikm, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    # RFC 8032 section 7.1, test 1: the public key, and that it validates.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = ed25519_public(seed)
    assert public.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed25519_valid(public)
    assert point_encode(point_mul(int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
                                  & ~7 & ((1 << 254) - 1) | (1 << 254), BASE)) == public
    # RFC 8032 section 7.1, test 1: the empty message, signed by the written-out
    # signing and verified strictly.
    rfc_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_sign_deterministic(seed, b"") == rfc_signature
    assert ed25519_verify_strict(public, b"", rfc_signature)
    # The written-out signing against `cryptography`, and the strict verifier
    # against both signatures and a signature with another nonce.
    seed = sha256(b"frasil spec example/possession-self-test")
    message = b"frasil possession self-test"
    public = ed25519_public(seed)
    ours = ed25519_sign_deterministic(seed, message)
    assert ours == ed25519_sign(seed, message), "RFC 8032 signing disagrees with cryptography"
    assert ed25519_verify_strict(public, message, ours) and ed25519_verify(public, message, ours)
    other = ed25519_sign_with_nonce(seed, message, 12345)
    assert other != ours and ed25519_verify_strict(public, message, other)
    assert ed25519_verify(public, message, other)
    assert not ed25519_verify_strict(public, message + b"!", ours)
    # RFC 7748 section 6.1: both key pairs and the shared secret.
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_public = x25519_public(alice)
    assert alice_public.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert x25519_function(alice, (9).to_bytes(32, "little")) == alice_public
    assert x25519_shared(bob, alice_public).hex() == (
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )
    assert x25519_valid(alice_public)
    # draft-irtf-cfrg-xchacha-03 section 2.2.1 and appendix A.3.1.
    assert hchacha20(
        bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")
    ).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    )
    sealed = xchacha20poly1305_seal(
        bytes(range(0x80, 0xA0)),
        bytes(range(0x40, 0x58)),
        plaintext,
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    assert sealed.hex() == (
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49"
    )
    # RFC 9180 appendix A.2.1: base mode, sequence number 0.
    sk_e = bytes.fromhex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
    pk_r = bytes.fromhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
    sk_r = bytes.fromhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    pt = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    enc, ct = hpke_seal(pk_r, info, bytes.fromhex("436f756e742d30"), pt, sk_e)
    assert enc.hex() == "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
    assert ct.hex() == (
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
    )
    assert hpke_open(sk_r, enc, info, bytes.fromhex("436f756e742d30"), ct) == pt
    # The same HPKE, without associated data, opened by `cryptography`'s own.
    from cryptography.hazmat.primitives import hpke

    enc, ct = hpke_seal(pk_r, info, b"", pt, sk_e)
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    assert suite.decrypt(enc + ct, X25519PrivateKey.from_private_bytes(sk_r), info) == pt
    # Point arithmetic: the base point has order L, and eight small-order points.
    assert point_equal(point_mul(L, BASE), IDENTITY)
    assert len({point_encode(q) for q in small_order_points()}) == 8
    assert ladder(L, 9, bits=L.bit_length())[1] == 0
