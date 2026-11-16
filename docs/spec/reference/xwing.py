"""X-Wing, and HPKE with X-Wing, written out for the reference script.

ML-KEM-768 follows FIPS 203 (Module-Lattice-Based Key-Encapsulation
Mechanism Standard, August 2024): its algorithm numbers are cited below.
X-Wing follows draft-connolly-cfrg-xwing-kem-06: a 32-byte decapsulation
key (a seed), ML-KEM-768 and X25519 combined with SHA3-256. HPKE follows
RFC 9180's base mode, with X-Wing as the KEM under the code point 0x647a,
which draft-ietf-hpke-pq calls MLKEM768-X25519: X-Wing's shared secret goes
straight into RFC 9180's key schedule, without DHKEM's ExtractAndExpand.

Nothing here comes from any implementation. Where a detail of the construction
is a choice the drafts leave to the implementation (the order of the
expanded seed, the split of the encapsulation randomness), the comments say
what an implementation does. `self_test` checks the code against the known answers
vendored in `kats/xwing.json`, whose "source" key names where each came
from.

Only the standard library (SHA-3 and SHAKE) and the `cryptography` package
(X25519, ChaCha20-Poly1305) are used. It is slow, and it is not constant
time: it is for test vectors only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from primitives import SpecError, hkdf_expand, hkdf_extract

# ---------------------------------------------------------------------------
# ML-KEM-768 (FIPS 203). Parameters: , table 2.

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4
ZETA = 17

EK_SIZE = 384 * K + 32  # 1184
DK_SIZE = 768 * K + 96  # 2400
CT_SIZE = 32 * (DU * K + DV)  # 1088


# The hash functions and the pseudorandom function.
def _h(s: bytes) -> bytes:
    return hashlib.sha3_256(s).digest()


def _j(s: bytes) -> bytes:
    return hashlib.shake_256(s).digest(32)


def _g(c: bytes) -> tuple[bytes, bytes]:
    out = hashlib.sha3_512(c).digest()
    return out[:32], out[32:]


def _prf(eta: int, s: bytes, b: int) -> bytes:
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# Compress_d and Decompress_d, rounding half up in integers.
def _compress(d: int, f: list[int]) -> list[int]:
    return [((x << (d + 1)) + Q) // (2 * Q) % (1 << d) for x in f]


def _decompress(d: int, f: list[int]) -> list[int]:
    return [(Q * y + (1 << (d - 1))) >> d for y in f]


# Algorithms 5 and 6: ByteEncode_d and ByteDecode_d. The 256 coefficients of
# d bits each, least significant bit first, packed little-endian.
def _byte_encode(d: int, f: list[int]) -> bytes:
    value = 0
    for i, a in enumerate(f):
        value |= a << (d * i)
    return value.to_bytes(32 * d, "little")


def _byte_decode(d: int, b: bytes) -> list[int]:
    assert len(b) == 32 * d
    value = int.from_bytes(b, "little")
    m = Q if d == 12 else 1 << d
    return [(value >> (d * i)) % (1 << d) % m for i in range(N)]


# Algorithm 7: SampleNTT. Rejection sampling from SHAKE128(rho || j || i).
def _sample_ntt(b: bytes) -> list[int]:
    assert len(b) == 34
    a: list[int] = []
    length = 3 * 168
    stream = hashlib.shake_128(b).digest(length)
    pos = 0
    while len(a) < N:
        if pos + 3 > len(stream):
            # hashlib's XOF restarts on each call, so ask for a longer output.
            length *= 2
            stream = hashlib.shake_128(b).digest(length)
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


# Algorithm 8: SamplePolyCBD_eta.
def _sample_poly_cbd(eta: int, b: bytes) -> list[int]:
    assert len(b) == 64 * eta
    bits = [(b[i // 8] >> (i % 8)) & 1 for i in range(8 * len(b))]
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


# The NTT. zeta^BitRev7(i) for i in 0..127, and the gammas of
# Algorithm 11, zeta^(2 BitRev7(i) + 1).
def _bitrev7(i: int) -> int:
    return int(f"{i:07b}"[::-1], 2)


_ZETAS = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]
_GAMMAS = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


# Algorithm 9: NTT.
def _ntt(f: list[int]) -> list[int]:
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = _ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


# Algorithm 10: NTT^-1.
def _ntt_inv(f: list[int]) -> list[int]:
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = _ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]  # 3303 = 128^-1 mod q


# Algorithms 11 and 12: MultiplyNTTs and BaseCaseMultiply.
def _multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * _GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _add(f: list[int], g: list[int]) -> list[int]:
    return [(a + b) % Q for a, b in zip(f, g)]


def _sub(f: list[int], g: list[int]) -> list[int]:
    return [(a - b) % Q for a, b in zip(f, g)]


def _matrix(rho: bytes) -> list[list[list[int]]]:
    """A-hat of Algorithms 13 and 14: A-hat[i][j] = SampleNTT(rho || j || i)."""
    return [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def _dot(row: list[list[int]], v: list[list[int]]) -> list[int]:
    acc = [0] * N
    for f, g in zip(row, v):
        acc = _add(acc, _multiply_ntts(f, g))
    return acc


# Algorithm 13: K-PKE.KeyGen(d).
def _kpke_keygen(d: bytes) -> tuple[bytes, bytes]:
    rho, sigma = _g(d + bytes([K]))
    a_hat = _matrix(rho)
    n = 0
    s = []
    for _ in range(K):
        s.append(_sample_poly_cbd(ETA1, _prf(ETA1, sigma, n)))
        n += 1
    e = []
    for _ in range(K):
        e.append(_sample_poly_cbd(ETA1, _prf(ETA1, sigma, n)))
        n += 1
    s_hat = [_ntt(p) for p in s]
    e_hat = [_ntt(p) for p in e]
    t_hat = [_add(_dot(a_hat[i], s_hat), e_hat[i]) for i in range(K)]
    ek = b"".join(_byte_encode(12, p) for p in t_hat) + rho
    dk = b"".join(_byte_encode(12, p) for p in s_hat)
    return ek, dk


# Algorithm 14: K-PKE.Encrypt(ek, m, r).
def _kpke_encrypt(ek: bytes, m: bytes, r: bytes) -> bytes:
    t_hat = [_byte_decode(12, ek[384 * i : 384 * (i + 1)]) for i in range(K)]
    rho = ek[384 * K : 384 * K + 32]
    a_hat = _matrix(rho)
    n = 0
    y = []
    for _ in range(K):
        y.append(_sample_poly_cbd(ETA1, _prf(ETA1, r, n)))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(_sample_poly_cbd(ETA2, _prf(ETA2, r, n)))
        n += 1
    e2 = _sample_poly_cbd(ETA2, _prf(ETA2, r, n))
    y_hat = [_ntt(p) for p in y]
    # u = NTT^-1(A-hat^T o y-hat) + e1: column i of A-hat is row i of A-hat^T.
    u = [_add(_ntt_inv(_dot([a_hat[j][i] for j in range(K)], y_hat)), e1[i]) for i in range(K)]
    mu = _decompress(1, _byte_decode(1, m))
    v = _add(_add(_ntt_inv(_dot(t_hat, y_hat)), e2), mu)
    c1 = b"".join(_byte_encode(DU, _compress(DU, p)) for p in u)
    c2 = _byte_encode(DV, _compress(DV, v))
    return c1 + c2


# Algorithm 15: K-PKE.Decrypt(dk, c).
def _kpke_decrypt(dk: bytes, c: bytes) -> bytes:
    c1, c2 = c[: 32 * DU * K], c[32 * DU * K :]
    u = [_decompress(DU, _byte_decode(DU, c1[32 * DU * i : 32 * DU * (i + 1)])) for i in range(K)]
    v = _decompress(DV, _byte_decode(DV, c2))
    s_hat = [_byte_decode(12, dk[384 * i : 384 * (i + 1)]) for i in range(K)]
    w = _sub(v, _ntt_inv(_dot(s_hat, [_ntt(p) for p in u])))
    return _byte_encode(1, _compress(1, w))


# Algorithm 16: ML-KEM.KeyGen_internal(d, z).
def mlkem768_keygen_internal(d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """Returns (ek, dk): ek of 1184 bytes, dk of 2400 bytes."""
    assert len(d) == 32 and len(z) == 32
    ek_pke, dk_pke = _kpke_keygen(d)
    return ek_pke, dk_pke + ek_pke + _h(ek_pke) + z


# Algorithm 17: ML-KEM.Encaps_internal(ek, m).
def mlkem768_encaps_internal(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Returns (K, c): the 32-byte shared key and the 1088-byte ciphertext."""
    assert len(ek) == EK_SIZE and len(m) == 32
    shared, r = _g(m + _h(ek))
    return shared, _kpke_encrypt(ek, m, r)


# Algorithm 18: ML-KEM.Decaps_internal(dk, c), with implicit rejection.
def mlkem768_decaps_internal(dk: bytes, c: bytes) -> bytes:
    assert len(dk) == DK_SIZE and len(c) == CT_SIZE
    dk_pke = dk[: 384 * K]
    ek_pke = dk[384 * K : 768 * K + 32]
    h = dk[768 * K + 32 : 768 * K + 64]
    z = dk[768 * K + 64 : 768 * K + 96]
    m_prime = _kpke_decrypt(dk_pke, c)
    shared_prime, r_prime = _g(m_prime + h)
    shared_bar = _j(z + c)
    c_prime = _kpke_encrypt(ek_pke, m_prime, r_prime)
    if c != c_prime:
        shared_prime = shared_bar
    return shared_prime


def mlkem768_encapsulation_key_valid(ek: bytes) -> bool:
    """FIPS 203 section 7.2, the encapsulation key check: the type check (1184
    bytes) and the modulus check (ByteEncode_12(ByteDecode_12(ek)) == ek over
    the first 384k bytes, i.e. every 12-bit coefficient below q). rho, the last
    32 bytes, is not checked."""
    if len(ek) != EK_SIZE:
        return False
    for i in range(K):
        chunk = ek[384 * i : 384 * (i + 1)]
        if _byte_encode(12, _byte_decode(12, chunk)) != chunk:
            return False
    return True


# ---------------------------------------------------------------------------
# X-Wing (draft-connolly-cfrg-xwing-kem-06), as `x-wing` 0.1.1 implements it.

XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # the ASCII "\.//^\"
XWING_PK_SIZE = EK_SIZE + 32  # 1216
XWING_CT_SIZE = CT_SIZE + 32  # 1120


def _x25519_public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def _x25519(secret: bytes, public: bytes) -> bytes:
    # `cryptography` raises on an all-zero result; X-Wing's DecapsulationKey in
    # x-wing 0.1.1 accepts it (non-contributory behaviour). The vectors here
    # never reach that case, and the caller would see the exception.
    return X25519PrivateKey.from_private_bytes(secret).exchange(
        X25519PublicKey.from_public_bytes(public)
    )


def _xwing_expand(seed: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """expandDecapsulationKey: SHAKE256(seed) to 96 bytes, read in order as
    ML-KEM's d (32), ML-KEM's z (32) and the X25519 secret (32). Returns
    (dk_M, sk_X, pk_M, pk_X)."""
    assert len(seed) == 32
    expanded = hashlib.shake_256(seed).digest(96)
    pk_m, dk_m = mlkem768_keygen_internal(expanded[0:32], expanded[32:64])
    sk_x = expanded[64:96]
    return dk_m, sk_x, pk_m, _x25519_public(sk_x)


def _xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_public_key(seed: bytes) -> bytes:
    """The 1216-byte encapsulation key pk_M (1184) || pk_X (32) of a 32-byte seed."""
    _, _, pk_m, pk_x = _xwing_expand(seed)
    return pk_m + pk_x


def xwing_encapsulate_derand(pk: bytes, eseed: bytes) -> tuple[bytes, bytes]:
    """Encapsulation with 64 bytes of randomness: the first 32 are ML-KEM's m,
    the last 32 the X25519 ephemeral secret (x-wing's encapsulate_deterministic).
    Returns (ct, ss): ct = ct_M (1088) || ct_X (32), ss of 32 bytes.

    Like x-wing's EncapsulationKey::new, refuses an ML-KEM key that fails the
    FIPS 203 section 7.2 check; the X25519 half is not checked."""
    if len(pk) != XWING_PK_SIZE or len(eseed) != 64:
        raise SpecError("InvalidKey")
    pk_m, pk_x = pk[:EK_SIZE], pk[EK_SIZE:]
    if not mlkem768_encapsulation_key_valid(pk_m):
        raise SpecError("InvalidKey")
    ss_m, ct_m = mlkem768_encaps_internal(pk_m, eseed[:32])
    ek_x = eseed[32:]
    ct_x = _x25519_public(ek_x)
    ss_x = _x25519(ek_x, pk_x)
    return ct_m + ct_x, _xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def xwing_decapsulate(seed: bytes, ct: bytes) -> bytes:
    """The 32-byte shared secret of a 1120-byte ciphertext."""
    if len(ct) != XWING_CT_SIZE:
        raise SpecError("Decapsulate")
    dk_m, sk_x, _, pk_x = _xwing_expand(seed)
    ct_m, ct_x = ct[:CT_SIZE], ct[CT_SIZE:]
    ss_m = mlkem768_decaps_internal(dk_m, ct_m)
    ss_x = _x25519(sk_x, ct_x)
    return _xwing_combiner(ss_m, ss_x, ct_x, pk_x)


# ---------------------------------------------------------------------------
# HPKE (RFC 9180) base mode with KEM 0x647a (MLKEM768-X25519, i.e. X-Wing),
# KDF HKDF-SHA256 (0x0001), AEAD ChaCha20-Poly1305 (0x0003), as `hpke` 0.14.1
# does it. Single shot, sequence number 0.

KEM_ID_XWING = 0x647A
XWING_KEM_SUITE = b"KEM" + KEM_ID_XWING.to_bytes(2, "big")
XWING_HPKE_SUITE = (
    b"HPKE" + KEM_ID_XWING.to_bytes(2, "big") + (1).to_bytes(2, "big") + (3).to_bytes(2, "big")
)


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    """RFC 9180 section 4."""
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    """RFC 9180 section 4."""
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def _labeled_derive_shake256(
    suite: bytes, ikm: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """draft-ietf-hpke-pq's SHAKE256 LabeledDerive (the one-stage KDF form):
    SHAKE256(ikm || "HPKE-v1" || suite || u16(len(label)) || label || u16(L) || context)."""
    return hashlib.shake_256(
        ikm
        + b"HPKE-v1"
        + suite
        + len(label).to_bytes(2, "big")
        + label
        + length.to_bytes(2, "big")
        + context
    ).digest(length)


def xwing_derive_key_pair(ikm: bytes) -> tuple[bytes, bytes]:
    """HPKE DeriveKeyPair for X-Wing: seed = SHAKE256.LabeledDerive(ikm,
    "DeriveKeyPair", "", 32) with suite id "KEM" || u16(0x647a). Returns
    (seed, pk)."""
    seed = _labeled_derive_shake256(XWING_KEM_SUITE, ikm, b"DeriveKeyPair", b"", 32)
    return seed, xwing_public_key(seed)


def _xwing_key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 section 5.1, KeySchedule for mode_base (psk and psk_id empty)."""
    psk_id_hash = _labeled_extract(XWING_HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(XWING_HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(XWING_HPKE_SUITE, shared_secret, b"secret", b"")
    key = _labeled_expand(XWING_HPKE_SUITE, secret, b"key", context, 32)
    nonce = _labeled_expand(XWING_HPKE_SUITE, secret, b"base_nonce", context, 12)
    return key, nonce


def hpke_xwing_seal(
    pk: bytes, info: bytes, aad: bytes, plaintext: bytes, eseed: bytes
) -> tuple[bytes, bytes]:
    """SetupBaseS with X-Wing's Encap on the 64 bytes eseed, then Seal with
    sequence number 0 (the nonce is base_nonce). Returns (enc, ciphertext):
    enc of 1120 bytes, the ciphertext with its 16-byte tag."""
    enc, shared_secret = xwing_encapsulate_derand(pk, eseed)
    key, nonce = _xwing_key_schedule(shared_secret, info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def hpke_xwing_open(seed: bytes, enc: bytes, info: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """SetupBaseR with X-Wing's Decap, then Open with sequence number 0."""
    shared_secret = xwing_decapsulate(seed, enc)
    key, nonce = _xwing_key_schedule(shared_secret, info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise SpecError("Decrypt") from error


# ---------------------------------------------------------------------------
# Self-test against the vendored known answers.

KATS = Path(__file__).resolve().parent / "kats" / "xwing.json"


def self_test() -> None:
    kats = json.loads(KATS.read_text())
    x = bytes.fromhex

    # ML-KEM-768 KeyGen_internal: the seed-form example key of ml-kem 0.3.2
    # (the 64-byte seed d || z), and its public key.
    case = kats["ml-kem-seed"]
    seed = x(case["seed"])
    ek, dk = mlkem768_keygen_internal(seed[:32], seed[32:])
    assert ek.hex() == case["ek"], "ML-KEM-768 KeyGen disagrees with the seed example"
    public_keys = [ek]

    # ML-KEM-768 through HPKE (kem 0x0041): DeriveKeyPair (SHAKE256
    # LabeledDerive to 64 bytes, d || z), KeyGen, Encaps with m = ikmE, Decaps.
    case = kats["ml-kem-hpke"]
    mlkem768_kem_suite = b"KEM" + (0x0041).to_bytes(2, "big")
    sk = _labeled_derive_shake256(mlkem768_kem_suite, x(case["ikmR"]), b"DeriveKeyPair", b"", 64)
    assert sk.hex() == case["skRm"], "ML-KEM DeriveKeyPair"
    ek, dk = mlkem768_keygen_internal(sk[:32], sk[32:])
    assert ek.hex() == case["pkRm"], "ML-KEM-768 KeyGen"
    shared, c = mlkem768_encaps_internal(ek, x(case["ikmE"]))
    assert c.hex() == case["enc"], "ML-KEM-768 Encaps ciphertext"
    assert shared.hex() == case["shared_secret"], "ML-KEM-768 Encaps shared key"
    assert mlkem768_decaps_internal(dk, c) == shared, "ML-KEM-768 Decaps"
    public_keys.append(ek)
    # Implicit rejection (Algorithm 18, line 9): a changed ciphertext yields
    # J(z || c), not the shared key. No vendored vector covers this branch, so
    # this checks only that it is taken.
    tampered = bytes([c[0] ^ 1]) + c[1:]
    rejected = mlkem768_decaps_internal(dk, tampered)
    assert rejected == _j(dk[-32:] + tampered) and rejected != shared, "implicit rejection"

    # X-Wing: the draft's vectors as x-wing 0.1.1 runs them (sk is the seed,
    # eseed the 64 bytes of encapsulation randomness).
    for case in kats["x-wing"]:
        seed = x(case["seed"])
        assert case["sk"] == case["seed"]
        pk = xwing_public_key(seed)
        assert pk.hex() == case["pk"], "X-Wing public key"
        ct, ss = xwing_encapsulate_derand(pk, x(case["eseed"]))
        assert ct.hex() == case["ct"], "X-Wing ciphertext"
        assert ss.hex() == case["ss"], "X-Wing shared secret"
        assert xwing_decapsulate(seed, ct) == ss, "X-Wing decapsulation"
        public_keys.append(pk[:EK_SIZE])

    # HPKE with X-Wing (hpke 0.14.1, pq-6433c8f.json): DeriveKeyPair from
    # ikmR, Encap with ikmE as the 64 bytes of randomness, the key schedule,
    # the first encryption, and opening it.
    case = kats["hpke-xwing"]
    seed, pk = xwing_derive_key_pair(x(case["ikmR"]))
    assert seed.hex() == case["skRm"], "X-Wing DeriveKeyPair seed"
    assert pk.hex() == case["pkRm"], "X-Wing DeriveKeyPair public key"
    enc, shared_secret = xwing_encapsulate_derand(pk, x(case["ikmE"]))
    assert enc.hex() == case["enc"], "HPKE X-Wing enc"
    assert shared_secret.hex() == case["shared_secret"], "HPKE X-Wing shared secret"
    info = x(case["info"])
    key, nonce = _xwing_key_schedule(shared_secret, info)
    assert key.hex() == case["key"] and nonce.hex() == case["base_nonce"], "HPKE key schedule"
    encryption = case["encryption"]
    aad, pt = x(encryption["aad"]), x(encryption["pt"])
    enc, ct = hpke_xwing_seal(pk, info, aad, pt, x(case["ikmE"]))
    assert enc.hex() == case["enc"] and ct.hex() == encryption["ct"], "HPKE X-Wing seal"
    assert hpke_xwing_open(seed, x(case["enc"]), info, aad, x(encryption["ct"])) == pt
    try:
        hpke_xwing_open(seed, enc, info, aad + b"!", ct)
    except SpecError as error:
        assert error.error == "Decrypt"
    else:
        raise AssertionError("HPKE X-Wing opened with the wrong associated data")
    public_keys.append(pk[:EK_SIZE])

    # FIPS 203 section 7.2: every vendored key passes; a coefficient of q, or
    # a key one byte short, does not.
    for ek in public_keys:
        assert mlkem768_encapsulation_key_valid(ek), "a vendored key fails the modulus check"
    ek = public_keys[0]
    # Set the second coefficient of the first polynomial (bytes 1 and 2:
    # the high nibble of byte 1, then byte 2) to q = 3329 = 0xd01.
    bad = bytearray(ek)
    bad[1] = (bad[1] & 0x0F) | ((Q & 0x0F) << 4)
    bad[2] = Q >> 4
    assert _byte_decode(12, bytes(bad[:384]))[1] == 0  # 3329 mod q
    assert not mlkem768_encapsulation_key_valid(bytes(bad)), "coefficient q accepted"
    assert not mlkem768_encapsulation_key_valid(ek[:-1]), "1183-byte key accepted"
    try:
        xwing_encapsulate_derand(bytes(bad) + bytes(32), bytes(64))
    except SpecError as error:
        assert error.error == "InvalidKey"
    else:
        raise AssertionError("X-Wing encapsulated to an invalid ML-KEM key")


if __name__ == "__main__":
    self_test()
    print("ok")
