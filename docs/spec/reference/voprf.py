"""RFC 9497's VOPRF, mode modeVOPRF (0x01), suite ristretto255-SHA512, and
the ristretto255 group of RFC 9496 it runs on, written out from the two
RFCs, independently of any implementation. crypto.md lists the VOPRF for
ext-deposit-tokens.md alone.

Elements are ristretto255 points in RFC 8032's extended coordinates
(primitives.py's Edwards arithmetic), scalars are integers modulo L. Every
random draw takes its bytes: the blind, the proof's random scalar and the
seed. The self-test runs RFC 9496's group vectors and RFC 9497's VOPRF
vectors for this suite, kept in kats/ristretto255-voprf.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from primitives import BASE, IDENTITY, L, P, D, SQRT_M1, SpecError, point_add, point_mul

# RFC 9496, section 4.1.
SQRT_AD_MINUS_ONE = \
    25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = \
    54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952

ELEMENT_BYTES = SCALAR_BYTES = 32  # Ne, Ns
OUTPUT_BYTES = 64  # Nh
MODE_VOPRF = 0x01
SUITE = b"ristretto255-SHA512"
CONTEXT = b"OPRFV1-" + bytes([MODE_VOPRF]) + b"-" + SUITE
G = BASE


def _is_negative(x: int) -> bool:
    return (x % P) & 1 == 1


def _abs(x: int) -> int:
    x %= P
    return (P - x) % P if _is_negative(x) else x


def sqrt_ratio_m1(u: int, v: int) -> tuple[bool, int]:
    """RFC 9496, section 4.2."""
    u, v = u % P, v % P
    v3 = v * v * v % P
    v7 = v3 * v3 * v % P
    r = u * v3 * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r * r % P
    correct = check == u
    flipped = check == (-u) % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return correct or flipped, _abs(r)


def decode(encoded: bytes):
    """RFC 9496, section 4.3.1: the element, or None where decoding fails: a
    non-canonical or negative s, a non-square, a negative x*y, or y = 0."""
    if len(encoded) != 32:
        return None
    s = int.from_bytes(encoded, "little")
    if s >= P or _is_negative(s):
        return None
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 * u1) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x * v % P
    x = _abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or _is_negative(t) or y == 0:
        return None
    return (x, y, 1, t)


def encode(point: tuple) -> bytes:
    """RFC 9496, section 4.3.2."""
    x0, y0, z0, t0 = (c % P for c in point)
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 * u2)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 * t0 % P
    ix0 = x0 * SQRT_M1 % P
    iy0 = y0 * SQRT_M1 % P
    enchanted_denominator = den1 * INVSQRT_A_MINUS_D % P
    rotate = _is_negative(t0 * z_inv)
    x, y = (iy0, ix0) if rotate else (x0, y0)
    den_inv = enchanted_denominator if rotate else den2
    if _is_negative(x * z_inv):
        y = (-y) % P
    s = _abs(den_inv * (z0 - y))
    return s.to_bytes(32, "little")


def equal(a: tuple, b: tuple) -> bool:
    """RFC 9496, section 4.3.3."""
    x1, y1, _, _ = a
    x2, y2, _, _ = b
    return (x1 * y2 - y1 * x2) % P == 0 or (y1 * y2 - x1 * x2) % P == 0


def _map(t: int) -> tuple:
    """RFC 9496, section 4.3.4, MAP."""
    r = SQRT_M1 * t * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = (-_abs(s * t)) % P
    if not was_square:
        s = s_prime
    c = (P - 1) if was_square else r
    n = (c * (r - 1) * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def from_uniform_bytes(b: bytes) -> tuple:
    """RFC 9496, section 4.3.4: an element from 64 uniform bytes."""
    assert len(b) == 64
    r0 = (int.from_bytes(b[:32], "little") & ((1 << 255) - 1)) % P
    r1 = (int.from_bytes(b[32:], "little") & ((1 << 255) - 1)) % P
    return point_add(_map(r0), _map(r1))


def is_identity(point: tuple) -> bool:
    return equal(point, IDENTITY)


# ---------------------------------------------------------------------------
# RFC 9497: the suite's functions (section 4.1) and the protocol (sections
# 2 and 3), in mode modeVOPRF.


def i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380, section 5.3.1, with SHA-512."""
    b_bytes, block = 64, 128
    ell = -(-length // b_bytes)
    assert ell <= 255 and length <= 65535 and len(dst) <= 255
    dst_prime = dst + i2osp(len(dst), 1)
    b0 = hashlib.sha512(bytes(block) + msg + i2osp(length, 2) + i2osp(0, 1) + dst_prime).digest()
    b = [hashlib.sha512(b0 + i2osp(1, 1) + dst_prime).digest()]
    for i in range(2, ell + 1):
        mixed = bytes(x ^ y for x, y in zip(b0, b[-1]))
        b.append(hashlib.sha512(mixed + i2osp(i, 1) + dst_prime).digest())
    return b"".join(b)[:length]


def hash_to_group(x: bytes) -> tuple:
    return from_uniform_bytes(expand_message_xmd(x, b"HashToGroup-" + CONTEXT, 64))


def hash_to_scalar(x: bytes, dst: bytes = b"HashToScalar-" + CONTEXT) -> int:
    return int.from_bytes(expand_message_xmd(x, dst, 64), "little") % L


def serialize_element(point: tuple) -> bytes:
    return encode(point)


def deserialize_element(encoded: bytes) -> tuple:
    """RFC 9497, section 4.1: refuses an encoding that does not decode, and
    the identity. Raises SpecError("Malformed"); a caller that reads a
    public key names its own class."""
    point = decode(encoded) if isinstance(encoded, bytes) else None
    if point is None or is_identity(point):
        raise SpecError("Malformed")
    return point


def serialize_scalar(s: int) -> bytes:
    return (s % L).to_bytes(32, "little")


def deserialize_scalar(encoded: bytes) -> int:
    """RFC 9497, section 4.1: 32 bytes, little-endian, below the order."""
    if len(encoded) != 32 or int.from_bytes(encoded, "little") >= L:
        raise SpecError("Malformed")
    return int.from_bytes(encoded, "little")


def derive_key_pair(seed: bytes, info: bytes) -> tuple[int, tuple]:
    """RFC 9497, section 3.2.1."""
    derive_input = seed + i2osp(len(info), 2) + info
    for counter in range(256):
        sk = hash_to_scalar(derive_input + i2osp(counter, 1), b"DeriveKeyPair" + CONTEXT)
        if sk != 0:
            return sk, point_mul(sk, G)
    raise SpecError("DeriveKeyPairError")


def blind(input_: bytes, blind_scalar: int) -> tuple:
    """RFC 9497, section 3.3.1 (Blind), with its random scalar given."""
    element = hash_to_group(input_)
    if is_identity(element):
        raise SpecError("InvalidInput")
    return point_mul(blind_scalar, element)


def blind_evaluate(sk: int, blinded: tuple) -> tuple:
    return point_mul(sk, blinded)


def _composites(k: int | None, b: tuple, cs: list, ds: list) -> tuple:
    """RFC 9497, section 2.2.1: ComputeComposites, and ComputeCompositesFast
    when the key k is known."""
    bm = serialize_element(b)
    seed_dst = b"Seed-" + CONTEXT
    seed = hashlib.sha512(i2osp(len(bm), 2) + bm + i2osp(len(seed_dst), 2) + seed_dst).digest()
    m, z = IDENTITY, IDENTITY
    for i, (c, d) in enumerate(zip(cs, ds)):
        ci, di_ = serialize_element(c), serialize_element(d)
        transcript = (i2osp(len(seed), 2) + seed + i2osp(i, 2) + i2osp(len(ci), 2) + ci
                      + i2osp(len(di_), 2) + di_ + b"Composite")
        di = hash_to_scalar(transcript)
        m = point_add(point_mul(di, c), m)
        if k is None:
            z = point_add(point_mul(di, d), z)
    if k is not None:
        z = point_mul(k, m)
    return m, z


def _challenge(b: tuple, m: tuple, z: tuple, t2: tuple, t3: tuple) -> int:
    parts = [serialize_element(e) for e in (b, m, z, t2, t3)]
    transcript = b"".join(i2osp(len(p), 2) + p for p in parts) + b"Challenge"
    return hash_to_scalar(transcript)


def generate_proof(k: int, a: tuple, b: tuple, cs: list, ds: list, r: int) -> bytes:
    """RFC 9497, section 2.2.1, with its random scalar r given; the proof
    serialized as SerializeScalar(c) || SerializeScalar(s)."""
    m, z = _composites(k, b, cs, ds)
    t2 = point_mul(r, a)
    t3 = point_mul(r, m)
    c = _challenge(b, m, z, t2, t3)
    s = (r - c * k) % L
    return serialize_scalar(c) + serialize_scalar(s)


def verify_proof(a: tuple, b: tuple, cs: list, ds: list, proof: bytes) -> bool:
    """RFC 9497, section 2.2.2. A proof whose scalars do not deserialize
    does not hold."""
    if len(proof) != 64:
        return False
    try:
        c = deserialize_scalar(proof[:32])
        s = deserialize_scalar(proof[32:])
    except SpecError:
        return False
    m, z = _composites(None, b, cs, ds)
    t2 = point_add(point_mul(s, a), point_mul(c, b))
    t3 = point_add(point_mul(s, m), point_mul(c, z))
    return _challenge(b, m, z, t2, t3) == c


def _finalize_hash(input_: bytes, element: tuple) -> bytes:
    e = serialize_element(element)
    return hashlib.sha512(i2osp(len(input_), 2) + input_ + i2osp(len(e), 2) + e
                          + b"Finalize").digest()


def finalize(input_: bytes, blind_scalar: int, evaluated: tuple) -> bytes:
    """RFC 9497, section 3.3.2, Finalize after its proof check: unblind,
    then hash."""
    return _finalize_hash(input_, point_mul(pow(blind_scalar, L - 2, L), evaluated))


def evaluate(sk: int, input_: bytes) -> bytes:
    """RFC 9497, section 3.3.2, the server's Evaluate."""
    element = hash_to_group(input_)
    if is_identity(element):
        raise SpecError("InvalidInput")
    return _finalize_hash(input_, point_mul(sk, element))


def scalar_from_bytes(seed: bytes) -> int:
    """A fixed non-zero scalar for the vectors, from 32 bytes: reduced
    modulo L. Its serialization is what a `_with` form takes."""
    s = int.from_bytes(seed, "little") % L
    assert s != 0
    return s


# ---------------------------------------------------------------------------
# Self-test: RFC 9496's group vectors, RFC 9497's VOPRF vectors.

KATS = Path(__file__).resolve().parent / "kats" / "ristretto255-voprf.json"


def kats() -> dict:
    return json.loads(KATS.read_text())


def rfc9497_case(vector: dict, sk: int, pk: tuple) -> dict:
    """One RFC 9497 vector run through this module: every intermediate
    value, as the vector lists it."""
    inputs = [bytes.fromhex(x) for x in vector["input"]]
    blinds = [deserialize_scalar(bytes.fromhex(x)) for x in vector["blind"]]
    blinded = [blind(i, b) for i, b in zip(inputs, blinds)]
    evaluated = [blind_evaluate(sk, e) for e in blinded]
    r = deserialize_scalar(bytes.fromhex(vector["proof_random_scalar"]))
    proof = generate_proof(sk, G, pk, blinded, evaluated, r)
    assert verify_proof(G, pk, blinded, evaluated, proof)
    outputs = [finalize(i, b, e) for i, b, e in zip(inputs, blinds, evaluated)]
    assert outputs == [evaluate(sk, i) for i in inputs]
    return {"name": vector["name"], "input": vector["input"], "blind": vector["blind"],
            "blinded_element": [serialize_element(e).hex() for e in blinded],
            "evaluation_element": [serialize_element(e).hex() for e in evaluated],
            "proof_random_scalar": vector["proof_random_scalar"], "proof": proof.hex(),
            "output": [o.hex() for o in outputs]}


def self_test() -> None:
    k = kats()
    # RFC 9496, A.1: multiples of the generator, which test encoding and
    # addition; each decodes back to itself.
    point = IDENTITY
    for expected in k["multiples_of_generator"]:
        assert encode(point).hex() == expected, expected
        if expected != "00" * 32:
            assert equal(decode(bytes.fromhex(expected)), point)
        point = point_add(point, G)
    assert decode(bytes(32)) is not None and is_identity(decode(bytes(32)))
    # A.2: every invalid encoding is refused.
    for bad in k["invalid_encodings"]:
        assert decode(bytes.fromhex(bad)) is None, bad
    # A.3: elements from uniform bytes.
    for uniform, expected in k["from_uniform_bytes"]:
        assert encode(from_uniform_bytes(bytes.fromhex(uniform))).hex() == expected
    # RFC 9497, A.1.2: the key pair and every vector, the batch included.
    v = k["voprf"]
    sk, pk = derive_key_pair(bytes.fromhex(v["seed"]), bytes.fromhex(v["key_info"]))
    assert serialize_scalar(sk).hex() == v["skSm"]
    assert serialize_element(pk).hex() == v["pkSm"]
    for vector in v["vectors"]:
        got = rfc9497_case(vector, sk, pk)
        for key in ("blinded_element", "evaluation_element", "proof", "output"):
            assert got[key] == vector[key], (vector["name"], key)
    # The identity and a non-canonical encoding are refused as elements.
    for bad in (bytes(32), (P + 2).to_bytes(32, "little")):
        try:
            deserialize_element(bad)
            raise AssertionError("accepted")
        except SpecError:
            pass


if __name__ == "__main__":
    self_test()
    print("ok")
