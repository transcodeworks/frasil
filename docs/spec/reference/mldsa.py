"""ML-DSA-65, written out for the reference script.

ML-DSA follows FIPS 204 (Module-Lattice-Based Digital Signature Standard,
August 2024); its algorithm numbers are cited below. Only the parameter set
ML-DSA-65 (table 1) is written out, because it is the one
crypto.md uses. Keys are generated from a 32-byte seed `xi`
(Algorithm 6), as `mldsa_keygen`. Signing is the deterministic variant of
Algorithm 2 (`rnd` is 32 zero bytes, section 3.4) unless a caller passes
`rnd`, so that a structure signed twice has one encoding.

Nothing here comes from any implementation. `self_test` checks the code against
the known answers vendored in `kats/mldsa65.json`: a subset of C2SP
Wycheproof's ML-DSA-65 vectors at the commit `generate.py` pins for its
Ed25519 and X25519 files; the file's "source" key says which. When the
`cryptography` package's backend provides ML-DSA (OpenSSL 3.5 or later), it
also checks key generation from a seed against it, and that each verifies
the other's signatures.

Only the standard library (SHAKE128, SHAKE256) is used. It is slow, and it
is not constant time: it is for test vectors only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Parameters: FIPS 204, section 4, table 1, ML-DSA-65.

Q = 8380417
ZETA = 1753
D = 13
TAU = 49
LAMBDA = 192
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32  # 261888
K = 6
L = 5
ETA = 4
BETA = TAU * ETA  # 196
OMEGA = 55
N = 256

C_TILDE_BYTES = LAMBDA // 4  # 48
PUBLIC_KEY_BYTES = 32 + 32 * K * 10  # 1952
SECRET_KEY_BYTES = 32 + 32 + 64 + 32 * ((L + K) * 4 + D * K)  # 4032
SIGNATURE_BYTES = C_TILDE_BYTES + L * 32 * 20 + OMEGA + K  # 3309
SEED_BYTES = 32


def _shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


class _Xof:
    """An incremental reader over SHAKE128 or SHAKE256.

    hashlib's XOF restarts on each call, so this asks for a longer output
    when it runs out, which gives the same stream."""

    def __init__(self, function, data: bytes) -> None:
        self._function = function
        self._data = data
        self._buffer = b""
        self._position = 0

    def read(self, count: int) -> bytes:
        while self._position + count > len(self._buffer):
            self._buffer = self._function(self._data).digest(max(2 * len(self._buffer), 1024))
        out = self._buffer[self._position : self._position + count]
        self._position += count
        return out


# ---------------------------------------------------------------------------
# Conversions. Bits are little-endian within bytes.


def _bits_of(data: bytes) -> int:
    return int.from_bytes(data, "little")


# Algorithm 16: SimpleBitPack(w, b): coefficients in [0, b], bitlen(b) bits each.
def _simple_bit_pack(w: list[int], b: int) -> bytes:
    bits = b.bit_length()
    value = 0
    for i, c in enumerate(w):
        assert 0 <= c <= b
        value |= c << (bits * i)
    return value.to_bytes(32 * bits, "little")


# Algorithm 17: BitPack(w, a, b): coefficients in [-a, b], stored as b - w.
def _bit_pack(w: list[int], a: int, b: int) -> bytes:
    bits = (a + b).bit_length()
    value = 0
    for i, c in enumerate(w):
        c = _centered(c)
        assert -a <= c <= b
        value |= (b - c) << (bits * i)
    return value.to_bytes(32 * bits, "little")


# Algorithm 18: SimpleBitUnpack(v, b).
def _simple_bit_unpack(v: bytes, b: int) -> list[int]:
    bits = b.bit_length()
    assert len(v) == 32 * bits
    value = _bits_of(v)
    mask = (1 << bits) - 1
    return [(value >> (bits * i)) & mask for i in range(N)]


# Algorithm 19: BitUnpack(v, a, b): each coefficient is b - z, returned mod q.
def _bit_unpack(v: bytes, a: int, b: int) -> list[int]:
    bits = (a + b).bit_length()
    assert len(v) == 32 * bits
    value = _bits_of(v)
    mask = (1 << bits) - 1
    return [(b - ((value >> (bits * i)) & mask)) % Q for i in range(N)]


# Algorithm 20: HintBitPack(h).
def _hint_bit_pack(h: list[list[int]]) -> bytes:
    y = bytearray(OMEGA + K)
    index = 0
    for i in range(K):
        for j in range(N):
            if h[i][j]:
                y[index] = j
                index += 1
        y[OMEGA + i] = index
    return bytes(y)


# Algorithm 21: HintBitUnpack(y). None is FIPS 204's bottom: a hint that is
# not in canonical form (indices out of order, a count that goes back or
# past omega, or nonzero padding).
def _hint_bit_unpack(y: bytes) -> list[list[int]] | None:
    h = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        if y[OMEGA + i] < index or y[OMEGA + i] > OMEGA:
            return None
        first = index
        while index < y[OMEGA + i]:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    for i in range(index, OMEGA):
        if y[i] != 0:
            return None
    return h


# Algorithms 22 to 28: the key and signature encodings.
def _pk_encode(rho: bytes, t1: list[list[int]]) -> bytes:
    return rho + b"".join(_simple_bit_pack(t1[i], (1 << 10) - 1) for i in range(K))


def _pk_decode(pk: bytes) -> tuple[bytes, list[list[int]]]:
    rho = pk[:32]
    t1 = [_simple_bit_unpack(pk[32 + 320 * i : 32 + 320 * (i + 1)], (1 << 10) - 1) for i in range(K)]
    return rho, t1


def _sk_encode(rho, key, tr, s1, s2, t0) -> bytes:
    out = rho + key + tr
    out += b"".join(_bit_pack(s1[i], ETA, ETA) for i in range(L))
    out += b"".join(_bit_pack(s2[i], ETA, ETA) for i in range(K))
    out += b"".join(_bit_pack(t0[i], (1 << (D - 1)) - 1, 1 << (D - 1)) for i in range(K))
    return out


def _sk_decode(sk: bytes):
    assert len(sk) == SECRET_KEY_BYTES
    rho, key, tr = sk[:32], sk[32:64], sk[64:128]
    pos = 128
    s1 = []
    for _ in range(L):
        s1.append(_bit_unpack(sk[pos : pos + 128], ETA, ETA))
        pos += 128
    s2 = []
    for _ in range(K):
        s2.append(_bit_unpack(sk[pos : pos + 128], ETA, ETA))
        pos += 128
    t0 = []
    for _ in range(K):
        t0.append(_bit_unpack(sk[pos : pos + 416], (1 << (D - 1)) - 1, 1 << (D - 1)))
        pos += 416
    assert pos == SECRET_KEY_BYTES
    return rho, key, tr, s1, s2, t0


def _sig_encode(c_tilde: bytes, z: list[list[int]], h: list[list[int]]) -> bytes:
    out = c_tilde + b"".join(_bit_pack(z[i], GAMMA1 - 1, GAMMA1) for i in range(L))
    return out + _hint_bit_pack(h)


def _sig_decode(sig: bytes):
    c_tilde = sig[:C_TILDE_BYTES]
    pos = C_TILDE_BYTES
    z = []
    for _ in range(L):
        z.append(_bit_unpack(sig[pos : pos + 640], GAMMA1 - 1, GAMMA1))
        pos += 640
    h = _hint_bit_unpack(sig[pos:])
    return c_tilde, z, h


def _w1_encode(w1: list[list[int]]) -> bytes:
    return b"".join(_simple_bit_pack(w1[i], (Q - 1) // (2 * GAMMA2) - 1) for i in range(K))


# ---------------------------------------------------------------------------
# Pseudorandom sampling.


# Algorithm 29: SampleInBall(rho), rho being all of c-tilde.
def _sample_in_ball(rho: bytes) -> list[int]:
    c = [0] * N
    xof = _Xof(hashlib.shake_256, rho)
    signs = _bits_of(xof.read(8))
    for i in range(N - TAU, N):
        j = xof.read(1)[0]
        while j > i:
            j = xof.read(1)[0]
        c[i] = c[j]
        c[j] = 1 if (signs >> (i + TAU - N)) & 1 == 0 else Q - 1
    return c


# Algorithm 30: RejNTTPoly(rho), with Algorithm 14, CoeffFromThreeBytes.
def _rej_ntt_poly(rho: bytes) -> list[int]:
    assert len(rho) == 34
    xof = _Xof(hashlib.shake_128, rho)
    a: list[int] = []
    while len(a) < N:
        b0, b1, b2 = xof.read(3)
        z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0
        if z < Q:
            a.append(z)
    return a


# Algorithm 31: RejBoundedPoly(rho), with Algorithm 15, CoeffFromHalfByte
# for eta = 4: a half byte b < 9 gives 4 - b.
def _rej_bounded_poly(rho: bytes) -> list[int]:
    assert len(rho) == 66
    xof = _Xof(hashlib.shake_256, rho)
    a: list[int] = []
    while len(a) < N:
        z = xof.read(1)[0]
        z0, z1 = z & 0x0F, z >> 4
        if z0 < 9:
            a.append((ETA - z0) % Q)
        if z1 < 9 and len(a) < N:
            a.append((ETA - z1) % Q)
    return a


# Algorithm 32: ExpandA. Algorithm 33: ExpandS. Algorithm 34: ExpandMask.
def _expand_a(rho: bytes) -> list[list[list[int]]]:
    return [[_rej_ntt_poly(rho + bytes([s, r])) for s in range(L)] for r in range(K)]


def _expand_s(rho: bytes) -> tuple[list[list[int]], list[list[int]]]:
    s1 = [_rej_bounded_poly(rho + r.to_bytes(2, "little")) for r in range(L)]
    s2 = [_rej_bounded_poly(rho + (r + L).to_bytes(2, "little")) for r in range(K)]
    return s1, s2


def _expand_mask(rho: bytes, mu: int) -> list[list[int]]:
    bits = 1 + (GAMMA1 - 1).bit_length()  # 20
    out = []
    for r in range(L):
        v = _shake256(rho + (mu + r).to_bytes(2, "little"), 32 * bits)
        out.append(_bit_unpack(v, GAMMA1 - 1, GAMMA1))
    return out


# ---------------------------------------------------------------------------
# Rounding.


def _centered(r: int, alpha: int = Q) -> int:
    """r mod+- alpha: the representative in (-alpha/2, alpha/2]."""
    r %= alpha
    return r - alpha if r > alpha // 2 else r


# Algorithm 35: Power2Round.
def _power2round(r: int) -> tuple[int, int]:
    r = r % Q
    r0 = _centered(r, 1 << D)
    return (r - r0) >> D, r0


# Algorithm 36: Decompose.
def _decompose(r: int) -> tuple[int, int]:
    r = r % Q
    r0 = _centered(r, 2 * GAMMA2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def _high_bits(r: int) -> int:
    return _decompose(r)[0]


def _low_bits(r: int) -> int:
    return _decompose(r)[1]


# Algorithm 39: MakeHint. Algorithm 40: UseHint.
def _make_hint(z: int, r: int) -> int:
    return int(_high_bits(r) != _high_bits(r + z))


def _use_hint(h: int, r: int) -> int:
    m = (Q - 1) // (2 * GAMMA2)
    r1, r0 = _decompose(r)
    if h == 1 and r0 > 0:
        return (r1 + 1) % m
    if h == 1 and r0 <= 0:
        return (r1 - 1) % m
    return r1


# ---------------------------------------------------------------------------
# The NTT. zetas[m] = zeta^BitRev8(m) mod q.


def _bitrev8(m: int) -> int:
    return int(f"{m:08b}"[::-1], 2)


_ZETAS = [pow(ZETA, _bitrev8(m), Q) for m in range(256)]
_N_INV = pow(N, Q - 2, Q)  # 8347681


# Algorithm 41.
def _ntt(w: list[int]) -> list[int]:
    a = list(w)
    m = 0
    length = 128
    while length >= 1:
        start = 0
        while start < N:
            m += 1
            z = _ZETAS[m]
            for j in range(start, start + length):
                t = z * a[j + length] % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length //= 2
    return a


# Algorithm 42.
def _ntt_inv(w: list[int]) -> list[int]:
    a = list(w)
    m = 256
    length = 1
    while length < N:
        start = 0
        while start < N:
            m -= 1
            z = Q - _ZETAS[m]
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = z * (t - a[j + length]) % Q
            start += 2 * length
        length *= 2
    return [x * _N_INV % Q for x in a]


def _pointwise(f: list[int], g: list[int]) -> list[int]:
    return [x * y % Q for x, y in zip(f, g)]


def _add(f: list[int], g: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(f, g)]


def _sub(f: list[int], g: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(f, g)]


def _matrix_times(a_hat, v_hat) -> list[list[int]]:
    """A-hat o v-hat, in the NTT domain, for a vector of length l."""
    out = []
    for row in a_hat:
        acc = [0] * N
        for a, v in zip(row, v_hat):
            acc = _add(acc, _pointwise(a, v))
        out.append(acc)
    return out


def _inf_norm(polys: list[list[int]]) -> int:
    return max(abs(_centered(c)) for p in polys for c in p)


# ---------------------------------------------------------------------------
# The internal functions.


# Algorithm 6: ML-DSA.KeyGen_internal(xi).
def mldsa_keygen(xi: bytes) -> tuple[bytes, bytes]:
    """The public key (1952 bytes) and the expanded secret key (4032 bytes)
    that the 32-byte seed `xi` determines."""
    if len(xi) != SEED_BYTES:
        raise ValueError("an ML-DSA seed is 32 bytes")
    expanded = _shake256(xi + bytes([K, L]), 128)
    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]
    a_hat = _expand_a(rho)
    s1, s2 = _expand_s(rho_prime)
    s1_hat = [_ntt(p) for p in s1]
    t = [_add(_ntt_inv(p), s2[i]) for i, p in enumerate(_matrix_times(a_hat, s1_hat))]
    t1, t0 = [], []
    for p in t:
        pairs = [_power2round(c) for c in p]
        t1.append([x for x, _ in pairs])
        t0.append([y % Q for _, y in pairs])
    pk = _pk_encode(rho, t1)
    tr = _shake256(pk, 64)
    sk = _sk_encode(rho, key, tr, s1, s2, t0)
    return pk, sk


def mldsa_public_key(xi: bytes) -> bytes:
    return mldsa_keygen(xi)[0]


def message_prime(message: bytes, context: bytes = b"") -> bytes:
    """Algorithm 2, line 10 (and Algorithm 3, line 5): M' for pure ML-DSA."""
    if len(context) > 255:
        raise ValueError("an ML-DSA context is at most 255 bytes")
    return bytes([0, len(context)]) + context + message


def mu_of(pk: bytes, m_prime: bytes) -> bytes:
    """Algorithm 7, line 6: mu = H(tr || M', 64), tr = H(pk, 64)."""
    return _shake256(_shake256(pk, 64) + m_prime, 64)


# Algorithm 7: ML-DSA.Sign_internal, from mu (lines 7 onward).
def sign_mu(sk: bytes, mu: bytes, rnd: bytes = bytes(32)) -> bytes:
    rho, key, _tr, s1, s2, t0 = _sk_decode(sk)
    s1_hat = [_ntt(p) for p in s1]
    s2_hat = [_ntt(p) for p in s2]
    t0_hat = [_ntt(p) for p in t0]
    a_hat = _expand_a(rho)
    rho_pp = _shake256(key + rnd + mu, 64)
    kappa = 0
    while True:
        y = _expand_mask(rho_pp, kappa)
        kappa += L
        w = [_ntt_inv(p) for p in _matrix_times(a_hat, [_ntt(p) for p in y])]
        w1 = [[_high_bits(c) for c in p] for p in w]
        c_tilde = _shake256(mu + _w1_encode(w1), C_TILDE_BYTES)
        c_hat = _ntt(_sample_in_ball(c_tilde))
        cs1 = [_ntt_inv(_pointwise(c_hat, p)) for p in s1_hat]
        cs2 = [_ntt_inv(_pointwise(c_hat, p)) for p in s2_hat]
        z = [_add(y[i], cs1[i]) for i in range(L)]
        w_minus = [_sub(w[i], cs2[i]) for i in range(K)]
        r0 = [[_low_bits(c) for c in p] for p in w_minus]
        if _inf_norm(z) >= GAMMA1 - BETA or max(abs(c) for p in r0 for c in p) >= GAMMA2 - BETA:
            continue
        ct0 = [_ntt_inv(_pointwise(c_hat, p)) for p in t0_hat]
        h = [
            [
                _make_hint((-ct0[i][j]) % Q, (w_minus[i][j] + ct0[i][j]) % Q)
                for j in range(N)
            ]
            for i in range(K)
        ]
        if _inf_norm(ct0) >= GAMMA2 or sum(map(sum, h)) > OMEGA:
            continue
        return _sig_encode(c_tilde, z, h)


def sign_internal(sk: bytes, pk: bytes, m_prime: bytes, rnd: bytes = bytes(32)) -> bytes:
    return sign_mu(sk, mu_of(pk, m_prime), rnd)


# Algorithm 2: ML-DSA.Sign, deterministic unless `rnd` is given.
def mldsa_sign(xi: bytes, message: bytes, context: bytes = b"", rnd: bytes = bytes(32)) -> bytes:
    pk, sk = mldsa_keygen(xi)
    return sign_internal(sk, pk, message_prime(message, context), rnd)


# Algorithm 8: ML-DSA.Verify_internal, with the lengths it implies.
def verify_internal(pk: bytes, m_prime: bytes, sig: bytes) -> bool:
    if len(pk) != PUBLIC_KEY_BYTES or len(sig) != SIGNATURE_BYTES:
        return False
    rho, t1 = _pk_decode(pk)
    c_tilde, z, h = _sig_decode(sig)
    if h is None:
        return False
    if _inf_norm(z) >= GAMMA1 - BETA:
        return False
    a_hat = _expand_a(rho)
    mu = mu_of(pk, m_prime)
    c_hat = _ntt(_sample_in_ball(c_tilde))
    az = _matrix_times(a_hat, [_ntt(p) for p in z])
    t1_hat = [_ntt([(c << D) % Q for c in p]) for p in t1]
    w_approx = [_ntt_inv(_sub(az[i], _pointwise(c_hat, t1_hat[i]))) for i in range(K)]
    w1 = [[_use_hint(h[i][j], w_approx[i][j]) for j in range(N)] for i in range(K)]
    return _shake256(mu + _w1_encode(w1), C_TILDE_BYTES) == c_tilde


# Algorithm 3: ML-DSA.Verify.
def mldsa_verify(pk: bytes, message: bytes, sig: bytes, context: bytes = b"") -> bool:
    if len(context) > 255:
        return False
    return verify_internal(pk, message_prime(message, context), sig)


# ---------------------------------------------------------------------------
# Self-test against the vendored known answers.

KATS = Path(__file__).resolve().parent / "kats" / "mldsa65.json"


def self_test() -> None:
    kats = json.loads(KATS.read_text())
    x = bytes.fromhex

    # The sizes table 2 gives.
    assert (PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES) == (1952, 4032, 3309)

    # Key generation and signing (Wycheproof sign_seed: a test without `rnd`
    # is deterministic; one with `rnd` is hedged with it). A test with `msg`
    # is signed through Algorithm 2; one with only `mu` (flag Internal) from
    # mu, as Algorithm 7 does after line 6.
    signed = 0
    for group in kats["sign"]:
        xi = x(group["privateSeed"])
        pk, sk = mldsa_keygen(xi)
        assert pk.hex() == group["publicKey"], "ML-DSA-65 KeyGen"
        for case in group["tests"]:
            rnd = x(case["rnd"]) if "rnd" in case else bytes(32)
            if case["result"] == "invalid":
                # Only an over-long context is vendored as invalid.
                assert len(x(case["ctx"])) > 255
                try:
                    message_prime(x(case["msg"]), x(case["ctx"]))
                except ValueError:
                    continue
                raise AssertionError("a context over 255 bytes was accepted")
            if "msg" in case:
                m_prime = message_prime(x(case["msg"]), x(case.get("ctx", "")))
                mu = mu_of(pk, m_prime)
                if "mu" in case:
                    assert mu.hex() == case["mu"], "ML-DSA-65 mu"
            else:
                mu = x(case["mu"])
            sig = sign_mu(sk, mu, rnd)
            assert sig.hex() == case["sig"], f"ML-DSA-65 signature, tcId {case['tcId']}"
            if "msg" in case:
                assert mldsa_verify(pk, x(case["msg"]), sig, x(case.get("ctx", "")))
            signed += 1
    assert signed >= 8

    # Verification, valid and invalid (Wycheproof verify).
    checked = 0
    for group in kats["verify"]:
        pk = x(group["publicKey"])
        for case in group["tests"]:
            ok = mldsa_verify(pk, x(case["msg"]), x(case["sig"]), x(case.get("ctx", "")))
            assert ok == (case["result"] == "valid"), f"ML-DSA-65 verify, tcId {case['tcId']}"
            checked += 1
    assert checked >= 20

    # A second implementation, when the backend has one.
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import mldsa as library
    except ImportError:
        return
    xi = bytes(range(32))
    try:
        theirs = library.MLDSA65PrivateKey.from_seed_bytes(xi)
    except UnsupportedAlgorithm:
        return
    pk, sk = mldsa_keygen(xi)
    assert theirs.public_key().public_bytes_raw() == pk, "KeyGen disagrees with the library"
    message, context = b"frasil", b"ctx"
    ours = mldsa_sign(xi, message, context)
    theirs.public_key().verify(ours, message, context)
    hedged = theirs.sign(message, context)
    assert mldsa_verify(pk, message, hedged, context), "a library signature is refused"
    try:
        theirs.public_key().verify(ours, message + b"!", context)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("the library accepted a changed message")


if __name__ == "__main__":
    self_test()
    print("ok")
