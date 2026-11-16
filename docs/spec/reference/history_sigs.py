"""Signature schemes 0 and 2, anchors and coverage (crypto.md, "Signature
schemes", "Verifying a signature", "Which structures carry which scheme",
"Anchors and coverage" and "The classical sunset").

A device's keys give its keys commitment and its device ID (crypto.md,
"A device's keys"):

    kc        = SHA-256("frasil/device-keys-commitment/v1" || field(mldsa)
                        || field(xwing))       xwing empty for a holder with none
    device ID = SHA-256("frasil/device-id/v1" || ed_public (32) || kc (32))

A scheme-2 signature over a structure's signed bytes `tbs` is

    m_ed      = "frasil/hybrid-signature/ed25519/v1" || ed_public (32) || tbs
    m_ml      = "frasil/hybrid-signature/mldsa/v1" || ed_public (32)
                || SHA-256(mldsa_public) (32) || tbs
    signature = Ed25519-Sign(ed_seed, m_ed) (64)
                || ML-DSA-65.Sign(mldsa key, m_ml, ctx = "") (3309)

The Ed25519 half verifies with the author's Ed25519 key alone, so a replica
refuses a stranger's forgery before it looks for any ML-DSA-65 key. The
ML-DSA-65 half verifies under the one ML-DSA-65 key that, with an X-Wing key
or none, hashes to the signer's `kc`, whatever source it came from. Both halves are
always required. ML-DSA-65 is signed deterministically, so a structure
signed twice has one encoding. `verify` makes the verifier's checks in
crypto.md's order; `coverage` decides which scheme-0 events a verifier
accepts after the classical sunset.

The ML-DSA-65 itself is `mldsa.py`, written out from FIPS 204 and checked
against Wycheproof's known answers. Nothing here comes from any implementation.
"""

from __future__ import annotations

import copy

import mldsa
import xwing
from formats import example
from primitives import (
    SpecError,
    ed25519_public,
    ed25519_sign_deterministic,
    ed25519_verify_strict,
    field,
    hkdf_expand,
    hkdf_extract,
    sha256,
)

# ---------------------------------------------------------------------------
# Notation.

SCHEME_ED25519 = 0
SCHEME_MLDSA65 = 1  # reserved; refused in protocol 1
SCHEME_HYBRID = 2

ED25519_SIGNATURE_BYTES = 64
HYBRID_SIGNATURE_BYTES = ED25519_SIGNATURE_BYTES + mldsa.SIGNATURE_BYTES  # 3373
MLDSA_PUBLIC_KEY_BYTES = mldsa.PUBLIC_KEY_BYTES  # 1952

HYBRID_ED25519_LABEL = b"frasil/hybrid-signature/ed25519/v1"
HYBRID_MLDSA_LABEL = b"frasil/hybrid-signature/mldsa/v1"
DEVICE_MLDSA_SEED_LABEL = b"frasil/device-mldsa-seed/v1"
DEVICE_HYBRID_SEED_LABEL = b"frasil/device-hybrid-seed/v1"
KEYS_COMMITMENT_LABEL = b"frasil/device-keys-commitment/v1"
DEVICE_ID_LABEL = b"frasil/device-id/v1"
RECOVERY_MLDSA_LABEL = b"frasil/recovery-key/mldsa/v1"
INVITE_MLDSA_LABEL = b"frasil/invite/mldsa/v1"
PASSKEY_MLDSA_LABEL = b"frasil/passkey/mldsa/v1"

# Labels the derivations use as HKDF salts (identity.md, ext-invite-links.md).
RECOVERY_SALT = b"frasil/recovery/v1"
INVITE_SALT = b"frasil/invite/v1"
PASSKEY_EXTRACT_SALT = b"frasil/passkey-extract/v1"

NEW_LABELS: list[bytes] = [
    HYBRID_ED25519_LABEL,
    HYBRID_MLDSA_LABEL,
    DEVICE_MLDSA_SEED_LABEL,
    KEYS_COMMITMENT_LABEL,
    DEVICE_ID_LABEL,
    RECOVERY_MLDSA_LABEL,
    INVITE_MLDSA_LABEL,
    PASSKEY_MLDSA_LABEL,
]

# crypto.md, "Which structures carry which scheme": the schemes each kind of
# event may carry, with events.md's kind numbers. Kinds 64 to 127 are
# ignorable; none is defined, and "ignorable" stands for them. Kind 3 is
# reserved: an event of kind 3 is refused before any signature is checked.
KIND_CODES = {"device-list": 1, "space": 2, "unit": 4, "anchor": 5,
              "storage": 6, "ignorable": 64}
RESERVED_KIND_CODES = (3,)
AUTHORITY_KINDS = ("device-list", "space", "anchor", "storage")
OPEN_KINDS = ("unit", "ignorable")
KINDS = AUTHORITY_KINDS + OPEN_KINDS


def allowed_schemes(kind: str, sunset: bool) -> tuple[int, ...]:
    """The schemes a verifier accepts on an event of `kind`, before or after
    the classical sunset."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    if kind in AUTHORITY_KINDS:
        return (SCHEME_HYBRID,)
    # Units and ignorable kinds: scheme 0 or 2 before the sunset; after it,
    # scheme 0 only when covered, which `verify` checks last.
    return (SCHEME_ED25519, SCHEME_HYBRID)


def signing_scheme(kind: str, sunset: bool) -> int:
    """The scheme an honest client signs an event of `kind` with."""
    if kind in AUTHORITY_KINDS or sunset:
        return SCHEME_HYBRID
    return SCHEME_ED25519


# ---------------------------------------------------------------------------
# ML-DSA-65 seeds.


def device_mldsa_seed_fixture(identity_seed: bytes) -> bytes:
    """A device generates its ML-DSA seed at random. Keys an application
    builds from an identity seed alone (fixtures, tests) take this one."""
    return sha256(DEVICE_MLDSA_SEED_LABEL + identity_seed)


def device_hybrid_seed_fixture(identity_seed: bytes) -> bytes:
    """The fixture derivation of a test device's X-Wing seed (crypto.md)."""
    return sha256(DEVICE_HYBRID_SEED_LABEL + identity_seed)


# ---------------------------------------------------------------------------
# A device's keys commitment and device ID (crypto.md, "A device's keys").


def keys_commitment(mldsa_public: bytes, xwing_public: bytes | None) -> bytes:
    """`kc`: the ML-DSA-65 key and the X-Wing key, each length-prefixed;
    the X-Wing key is the empty string for a holder that has none (a
    recovery agent, an administrator pseudonym)."""
    return sha256(KEYS_COMMITMENT_LABEL + field(mldsa_public) + field(xwing_public or b""))


def device_id(ed_public: bytes, kc: bytes) -> bytes:
    """The device ID of an Ed25519 key and a keys commitment."""
    assert len(ed_public) == 32 and len(kc) == 32
    return sha256(DEVICE_ID_LABEL + ed_public + kc)


def device_id_of(ed_public: bytes, mldsa_public: bytes, xwing_public: bytes | None) -> bytes:
    """The device ID of three public keys, the X-Wing key None for none."""
    return device_id(ed_public, keys_commitment(mldsa_public, xwing_public))


def keys_for(kc: bytes, candidates) -> tuple | None:
    """Keys by their hash (crypto.md, "Keys by their hash"): among
    `candidates`, (ML-DSA-65 key, X-Wing key or None) pairs from any source,
    the pair that hashes to `kc`, or None. No source is trusted: a pair that
    does not hash to `kc` is not the holder's, and only one pair does."""
    for mldsa_public, xwing_public in candidates:
        if mldsa_key_valid(mldsa_public) and keys_commitment(mldsa_public, xwing_public) == kc:
            return (mldsa_public, xwing_public)
    return None


def recovery_mldsa_seed(secret: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(RECOVERY_SALT, secret), RECOVERY_MLDSA_LABEL, 32)


def invite_mldsa_seed(secret: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(INVITE_SALT, secret), INVITE_MLDSA_LABEL, 32)


def passkey_mldsa_seed(prf_output: bytes, person_id: bytes) -> bytes:
    prk = hkdf_extract(PASSKEY_EXTRACT_SALT, prf_output)
    return hkdf_expand(prk, PASSKEY_MLDSA_LABEL + field(person_id), 32)


_XWING_PUBLIC: dict = {}


def xwing_public_of(seed: bytes) -> bytes:
    if seed not in _XWING_PUBLIC:
        _XWING_PUBLIC[seed] = xwing.xwing_public_key(seed)
    return _XWING_PUBLIC[seed]


class Signer:
    """A holder of keys that signs scheme 2: its Ed25519 seed, its ML-DSA-65
    seed, and its X-Wing seed or key, or none for a holder that has none; with
    the keys commitment and device ID they give."""

    def __init__(self, name: str, ed_seed: bytes, mldsa_seed: bytes,
                 xwing_seed: bytes | None = None, *, xwing_public: bytes | None = None) -> None:
        self.name = name
        self.ed_seed = ed_seed
        self.ed_public = ed25519_public(ed_seed)
        self.mldsa_seed = mldsa_seed
        self.mldsa_public, self._mldsa_secret = mldsa.mldsa_keygen(mldsa_seed)
        self.xwing_seed = xwing_seed
        self.xwing_public = xwing_public_of(xwing_seed) if xwing_seed is not None \
            else xwing_public
        self.kc = keys_commitment(self.mldsa_public, self.xwing_public)
        self.device_id = device_id(self.ed_public, self.kc)

    @property
    def keys(self) -> tuple:
        """(ML-DSA-65 key, X-Wing key or None): what `kc` commits to."""
        return (self.mldsa_public, self.xwing_public)

    @property
    def signer_bytes(self) -> bytes:
        """`ed || kc`, 64 bytes: what a structure outside an envelope carries."""
        return self.ed_public + self.kc


def fixture_signer(seed: bytes, name: str = "") -> Signer:
    """A test device's keys from its identity seed alone: crypto.md's
    fixture derivations of the ML-DSA-65 and X-Wing seeds."""
    return Signer(name, seed, device_mldsa_seed_fixture(seed), device_hybrid_seed_fixture(seed))


def device_signer(name: str) -> Signer:
    seed = example(f"{name}/ed25519")  # formats.device's identity seed
    return fixture_signer(seed, name)


def split_signer(value: bytes) -> tuple:
    """`ed || kc` as (ed, kc, device ID); the caller checks the length."""
    assert len(value) == 64
    return value[:32], value[32:], device_id(value[:32], value[32:])


# ---------------------------------------------------------------------------
# The signature.


def hybrid_ed25519_message(ed_public: bytes, tbs: bytes) -> bytes:
    """What the Ed25519 half of a scheme-2 signature signs."""
    assert len(ed_public) == 32
    return HYBRID_ED25519_LABEL + ed_public + tbs


def hybrid_mldsa_message(ed_public: bytes, mldsa_public: bytes, tbs: bytes) -> bytes:
    """What the ML-DSA-65 half signs; it binds both keys."""
    assert len(ed_public) == 32 and len(mldsa_public) == MLDSA_PUBLIC_KEY_BYTES
    return HYBRID_MLDSA_LABEL + ed_public + sha256(mldsa_public) + tbs


def verify_ed25519_half(ed: bytes, tbs: bytes, signature: bytes) -> bool:
    """The Ed25519 half of a 3,373-byte scheme-2 signature, strictly, under
    the signer's Ed25519 key with no other key. False for another length."""
    if len(signature) != HYBRID_SIGNATURE_BYTES or len(ed) != 32:
        return False
    return ed25519_verify_strict(ed, hybrid_ed25519_message(ed, tbs),
                                 signature[:ED25519_SIGNATURE_BYTES])


def verify_mldsa_half(ed: bytes, mldsa_public: bytes, tbs: bytes, signature: bytes) -> bool:
    """The ML-DSA-65 half, under the ML-DSA-65 key whose hash the signer's
    `kc` holds. False for another length."""
    if len(signature) != HYBRID_SIGNATURE_BYTES or not mldsa_key_valid(mldsa_public):
        return False
    return mldsa.mldsa_verify(mldsa_public, hybrid_mldsa_message(ed, mldsa_public, tbs),
                              signature[ED25519_SIGNATURE_BYTES:])


def sign(signer: Signer, scheme: int, tbs: bytes) -> bytes:
    if scheme == SCHEME_ED25519:
        return ed25519_sign_deterministic(signer.ed_seed, tbs)
    assert scheme == SCHEME_HYBRID
    m_ed = hybrid_ed25519_message(signer.ed_public, tbs)
    m_ml = hybrid_mldsa_message(signer.ed_public, signer.mldsa_public, tbs)
    ed = ed25519_sign_deterministic(signer.ed_seed, m_ed)
    ml = mldsa.sign_internal(signer._mldsa_secret, signer.mldsa_public, mldsa.message_prime(m_ml))
    return ed + ml


def mldsa_key_valid(key: bytes) -> bool:
    """Every 1952-byte string decodes (FIPS 204, Algorithm 23,
    has no failure), so the length is the whole check."""
    return len(key) == MLDSA_PUBLIC_KEY_BYTES


# ---------------------------------------------------------------------------
# The verifier's checks, in order.


def verify(
    kind: str,
    scheme: int,
    ed: bytes,
    kc: bytes,
    tbs: bytes,
    signature: bytes,
    *,
    keys=(),
    sunset: bool = False,
    covered: bool = True,
) -> None:
    """Return if the signature is accepted; raise SpecError with the class
    otherwise (crypto.md, "Verifying a signature"). `ed` and `kc` name the
    signer; `keys` are the (ML-DSA-65 key, X-Wing key or None) pairs the
    verifier holds from any source, of which only one can hash to `kc`.
    `covered` says whether an accepted scheme-2 event covers this one; it
    matters only after the sunset."""
    # 1. A scheme this verifier knows.
    if scheme not in (SCHEME_ED25519, SCHEME_HYBRID):
        raise SpecError("UnsupportedVersion")
    # 2. A scheme this kind may carry.
    if scheme not in allowed_schemes(kind, sunset):
        raise SpecError("SchemeNotAllowed")
    # 3. The signature's length for the scheme.
    expected = ED25519_SIGNATURE_BYTES if scheme == SCHEME_ED25519 else HYBRID_SIGNATURE_BYTES
    if len(signature) != expected:
        raise SpecError("Malformed")
    # 4. Ed25519, strictly, with `ed` alone: over tbs for scheme 0, over m_ed
    #    for scheme 2.
    if scheme == SCHEME_ED25519:
        if not ed25519_verify_strict(ed, tbs, signature):
            raise SpecError("BadSignature")
    elif not verify_ed25519_half(ed, tbs, signature):
        raise SpecError("BadSignature")
    # 5. For scheme 2, an ML-DSA-65 key that, with an X-Wing key or none,
    #    hashes to kc.
    held = keys_for(kc, keys) if scheme == SCHEME_HYBRID else None
    if scheme == SCHEME_HYBRID and held is None:
        raise SpecError("NoHybridKey")
    # 6. ML-DSA-65 over m_ml, with an empty context.
    if scheme == SCHEME_HYBRID and not verify_mldsa_half(ed, held[0], tbs, signature):
        raise SpecError("BadSignature")
    # 7. After the sunset, a scheme-0 event waits until it is covered.
    if sunset and scheme == SCHEME_ED25519 and not covered:
        raise SpecError("Uncovered")


# ---------------------------------------------------------------------------
# Coverage.


def coverage(events: list[dict], sunset: bool, held_before_sunset: tuple = ()) -> dict:
    """Which events a verifier accepts, given events whose signatures verify.

    Each event is {"id", "scheme", "refs"}: `refs` are the IDs of the events
    its envelope names by hash, its previous event and its parents. Refs to
    other logs travel sealed in bodies and never count. Before
    the sunset every event is accepted. After it,
    a scheme-2 event is accepted, and a scheme-0 event is accepted if an
    accepted scheme-2 event reaches it through refs, through any events, or
    if this verifier held it before its sunset. Others are "Uncovered":
    pending, never applied, and accepted later if a covering event arrives.
    """
    by_id = {e["id"]: e for e in events}
    if not sunset:
        return {e["id"]: "accepted" for e in events}
    reached: set[str] = set()
    stack = [e["id"] for e in events if e["scheme"] == SCHEME_HYBRID]
    while stack:
        current = stack.pop()
        if current in reached:
            continue
        reached.add(current)
        stack.extend(r for r in by_id[current]["refs"] if r in by_id)
    out = {}
    for e in events:
        if e["scheme"] == SCHEME_HYBRID or e["id"] in reached or e["id"] in held_before_sunset:
            out[e["id"]] = "accepted"
        else:
            out[e["id"]] = "Uncovered"
    return out


# ---------------------------------------------------------------------------
# Vectors.


def _events():
    # events.py imports this module, so it is imported here, when needed.
    import events

    return events


def build_event(signer: Signer, kind: str, body: bytes, *, scheme: int | None = None,
                log: bytes | None = None, seq: int = 1, prev: bytes | None = None,
                parents=()) -> dict:
    """A real event (events.md), built and signed with events.py:
    its map's bytes, tbs, the signed event, its ID (a hash of the unsigned
    bytes) and its signature."""
    ev = _events()
    fields = ev.event_fields(KIND_CODES[kind], signer, seq, body, log=log,
                             prev=prev, parents=parents, scheme=scheme)
    signed = ev.sign_fields(fields, signer)
    event_bytes, signature = ev.uncbor(signed)
    return {
        "kind": kind,
        "scheme": fields.get(ev.F_SCHEME, SCHEME_ED25519),
        "event": event_bytes,
        "tbs": ev.signing_input(event_bytes),
        "signed": signed,
        "id": ev.event_id(event_bytes),  # events.md: the unsigned bytes
        "signature": signature,
    }


def _expect(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return error.error
    return "accepted"


def signature_vectors() -> dict:
    """crypto.json's kind_policy, signatures, signature_refusals and
    coverage."""
    from primitives import L, ed25519_sign_with_nonce

    h = bytes.hex
    laptop = device_signer("laptop")
    phone = device_signer("phone")

    # Real events (events.md): the laptop founds a space and rotates its key
    # in a second space event, then anchors; the phone starts its person's
    # list and writes two units in the laptop's space. The bodies stand in for
    # sealed space-event bodies (roster.md): only signatures are tested here.
    genesis = build_event(laptop, "space", b"example space genesis")
    space = genesis["id"]
    key_event = build_event(laptop, "space", b"example space event that only rotates",
                            log=space, seq=2, prev=genesis["id"], parents=[genesis["id"]])
    anchor = build_event(laptop, "anchor", b"", log=space, seq=3,
                         prev=key_event["id"], parents=[key_event["id"]])
    list_genesis = build_event(phone, "device-list", b"example device-list genesis")
    unit0 = build_event(phone, "unit", b"example unit", log=space, seq=1,
                        parents=[key_event["id"]])
    unit2 = build_event(phone, "unit", b"example unit under scheme 2", scheme=SCHEME_HYBRID,
                        log=space, seq=2, prev=unit0["id"], parents=[unit0["id"]])
    built = [(laptop, genesis), (laptop, key_event), (laptop, anchor),
             (phone, list_genesis), (phone, unit0), (phone, unit2)]
    ev = _events()
    signatures = []
    signed = {}
    for signer, e in built:
        sig, tbs = e["signature"], e["tbs"]
        verify(e["kind"], e["scheme"], signer.ed_public, signer.kc, tbs, sig, keys=[signer.keys])
        decoded = ev.decode_event(e["signed"])  # events.md, "Decoding an event"
        ev.verify_hybrid(decoded, [signer.keys])
        assert decoded.id == e["id"] and decoded.author == signer.device_id
        entry = {"kind": e["kind"], "kind_code": KIND_CODES[e["kind"]], "signer": signer.name,
                 "scheme": e["scheme"], "event": h(e["event"]), "tbs": h(tbs)}
        if e["scheme"] == SCHEME_HYBRID:
            m_ed = hybrid_ed25519_message(signer.ed_public, tbs)
            m_ml = hybrid_mldsa_message(signer.ed_public, signer.mldsa_public, tbs)
            entry["ed25519_message"] = h(m_ed)
            entry["mldsa_message"] = h(m_ml)
            entry["mldsa_message_prime"] = h(mldsa.message_prime(m_ml))
            entry["ed25519_signature"] = h(sig[:64])
            entry["mldsa_signature"] = h(sig[64:])
        entry["signature"] = h(sig)
        entry["signature_length"] = len(sig)
        entry["signed_event"] = h(e["signed"])
        entry["event_id"] = h(e["id"])
        signatures.append(entry)
        signed.setdefault((e["kind"], e["scheme"]), (signer, tbs, sig))

    # Negative cases: (description, kind, scheme as stated, signer's ed and
    # kc, tbs, signature, the keys the verifier holds, sunset, covered).
    signer, tbs, sig = signed[("space", SCHEME_HYBRID)]
    unit_signer, unit_tbs, unit_sig = signed[("unit", SCHEME_ED25519)]
    other_signer, other_tbs, other_sig = laptop, key_event["tbs"], key_event["signature"]
    flipped_ed = bytes([sig[0] ^ 1]) + sig[1:]
    flipped_ml = sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]
    # An ML-DSA signature over the bare tbs, without the label and keys.
    bare_ml = mldsa.sign_internal(signer._mldsa_secret, signer.mldsa_public, mldsa.message_prime(tbs))
    # The same roster genesis under scheme 0 (key 9 absent).
    ed_only_event = build_event(signer, "space", b"example space genesis", scheme=SCHEME_ED25519)
    ed_only_tbs, ed_only = ed_only_event["tbs"], ed_only_event["signature"]
    # A scheme-2 roster event's halves moved under scheme 0 bytes.
    stripped = sig[:64]
    # The two halves of two different events.
    mixed = sig[:64] + other_sig[64:]
    # The ML-DSA half under the phone's ML-DSA key: the verifier holds the
    # laptop's, so the message binds another key.
    phone_m = hybrid_mldsa_message(signer.ed_public, phone.mldsa_public, tbs)
    phone_ml = mldsa.sign_internal(phone._mldsa_secret, phone.mldsa_public, mldsa.message_prime(phone_m))
    wrong_key = sig[:64] + phone_ml
    # Each half over the other half's message.
    m_ed = hybrid_ed25519_message(signer.ed_public, tbs)
    m_ml = hybrid_mldsa_message(signer.ed_public, signer.mldsa_public, tbs)
    ed_over_ml = ed25519_sign_deterministic(signer.ed_seed, m_ml) + sig[64:]
    ml_over_ed = sig[:64] + mldsa.sign_internal(signer._mldsa_secret, signer.mldsa_public,
                                                mldsa.message_prime(m_ed))
    # An Ed25519 half whose S is not reduced, and one whose R is the neutral
    # point (a nonce of 0), both made by the key's holder.
    s_big = (int.from_bytes(sig[32:64], "little") + L).to_bytes(32, "little")
    unreduced = sig[:32] + s_big + sig[64:]
    small_r = ed25519_sign_with_nonce(signer.ed_seed, m_ed, 0) + sig[64:]
    # A forger that signs Ed25519 for the laptop's key, beside an ML-DSA-65
    # key and an X-Wing key of its own: its key set has a `kc` of its own,
    # so it signs in full, as another device ID.
    forger = Signer("forger", signer.ed_seed, sha256(b"frasil spec example/crypto/forger/mldsa"),
                    sha256(b"frasil spec example/crypto/forger/xwing"))
    forged = build_event(forger, "space", b"example space genesis")
    assert forger.device_id != signer.device_id
    # The same forger under the laptop's own kc: the envelope names the
    # laptop, and its ML-DSA-65 half is the forger's.
    impostor = copy.copy(forger)
    impostor.kc, impostor.device_id = signer.kc, signer.device_id
    framed = build_event(impostor, "space", b"example space genesis")
    ed, kc = signer.ed_public, signer.kc
    own, phones = [signer.keys], [phone.keys]
    cases = [
        ("an unknown scheme, 3", "space", 3, ed, kc, tbs, sig, own, False, True),
        ("scheme 1, ML-DSA-65 alone: reserved and refused", "space", SCHEME_MLDSA65, ed, kc, tbs, sig[64:], own, False, True),
        ("a space event under scheme 0", "space", SCHEME_ED25519, ed, kc, ed_only_tbs, ed_only, own, False, True),
        ("a device-list event under scheme 0", "device-list", SCHEME_ED25519, ed, kc, ed_only_tbs, ed_only, own, False, True),
        ("an anchor under scheme 0", "anchor", SCHEME_ED25519, ed, kc, ed_only_tbs, ed_only, own, False, True),
        ("the Ed25519 half of a scheme-2 signature alone", "space", SCHEME_HYBRID, ed, kc, tbs, stripped, own, False, True),
        ("a scheme-2 signature one byte short", "space", SCHEME_HYBRID, ed, kc, tbs, sig[:-1], own, False, True),
        ("a scheme-0 signature one byte long", "unit", SCHEME_ED25519, unit_signer.ed_public, unit_signer.kc, unit_tbs, unit_sig + b"\x00", [], False, True),
        ("no ML-DSA-65 key held", "space", SCHEME_HYBRID, ed, kc, tbs, sig, [], False, True),
        ("an ML-DSA-65 key held whose hash, with its X-Wing key, is not the signer's kc: another device's", "space", SCHEME_HYBRID, ed, kc, tbs, sig, phones, False, True),
        ("a stranger's forgery under the laptop's key, its ML-DSA key not yet held: refused at the Ed25519 half, never pending", "space", SCHEME_HYBRID, ed, kc, tbs, flipped_ed, [], False, True),
        ("the Ed25519 half over the ML-DSA half's message", "space", SCHEME_HYBRID, ed, kc, tbs, ed_over_ml, own, False, True),
        ("the ML-DSA half over the Ed25519 half's message", "space", SCHEME_HYBRID, ed, kc, tbs, ml_over_ed, own, False, True),
        ("an ML-DSA key of the wrong length", "space", SCHEME_HYBRID, ed, kc, tbs, sig, [(signer.mldsa_public[:-1], signer.xwing_public)], False, True),
        ("the Ed25519 half changed", "space", SCHEME_HYBRID, ed, kc, tbs, flipped_ed, own, False, True),
        ("the ML-DSA half changed", "space", SCHEME_HYBRID, ed, kc, tbs, flipped_ml, own, False, True),
        ("the ML-DSA half over the bare signed bytes, without the label and keys", "space", SCHEME_HYBRID, ed, kc, tbs, sig[:64] + bare_ml, own, False, True),
        ("halves of two different events", "space", SCHEME_HYBRID, ed, kc, tbs, mixed, own, False, True),
        ("the ML-DSA half by another device's ML-DSA key, under the laptop's kc", "space", SCHEME_HYBRID, ed, kc, tbs, wrong_key, own + phones, False, True),
        ("another author", "space", SCHEME_HYBRID, phone.ed_public, phone.kc, tbs, sig, own + phones, False, True),
        ("a forgery that reuses the laptop's Ed25519 key under a kc of its own: accepted, as another device ID", "space", SCHEME_HYBRID, ed, forger.kc, forged["tbs"], forged["signature"], own + [forger.keys], False, True),
        ("the same forger's event under the laptop's own kc", "space", SCHEME_HYBRID, ed, kc, framed["tbs"], framed["signature"], own + [forger.keys], False, True),
        ("a changed byte of the signed bytes", "space", SCHEME_HYBRID, ed, kc, tbs[:-1] + b"!", sig, own, False, True),
        ("a scheme-0 unit after the sunset, not covered", "unit", SCHEME_ED25519, unit_signer.ed_public, unit_signer.kc, unit_tbs, unit_sig, [], True, False),
        ("a scheme-0 unit after the sunset, covered", "unit", SCHEME_ED25519, unit_signer.ed_public, unit_signer.kc, unit_tbs, unit_sig, [], True, True),
        ("a scheme-0 unit before the sunset, not covered", "unit", SCHEME_ED25519, unit_signer.ed_public, unit_signer.kc, unit_tbs, unit_sig, [], False, False),
        ("a scheme-0 unit before the sunset, covered", "unit", SCHEME_ED25519, unit_signer.ed_public, unit_signer.kc, unit_tbs, unit_sig, [], False, True),
        ("an Ed25519 half whose S is not reduced", "space", SCHEME_HYBRID, ed, kc, tbs, unreduced, own, False, True),
        ("an Ed25519 half whose R is of small order", "space", SCHEME_HYBRID, ed, kc, tbs, small_r, own, False, True),
    ]
    negative = []
    for description, kind, scheme, c_ed, c_kc, case_tbs, case_sig, keys, sunset, covered in cases:
        negative.append({
            "name": description,
            "kind": kind,
            "scheme": scheme,
            "ed": h(c_ed),
            "kc": h(c_kc),
            "author": h(device_id(c_ed, c_kc)),
            "tbs": h(case_tbs),
            "signature": h(case_sig),
            "keys_held": [{"mldsa_sha256": h(sha256(m)), "mldsa_length": len(m),
                           "xwing_sha256": None if x is None else h(sha256(x))}
                          for m, x in keys],
            "sunset": sunset,
            "covered": covered,
            "expected": _expect(verify, kind, scheme, c_ed, c_kc, case_tbs, case_sig,
                                keys=keys, sunset=sunset, covered=covered),
        })

    # Coverage. u and f: scheme-0 units, A: scheme-2 anchors.
    graphs = [
        ("a chain of units under an anchor",
         [{"id": "u1", "scheme": 0, "refs": []},
          {"id": "u2", "scheme": 0, "refs": ["u1"]},
          {"id": "u3", "scheme": 0, "refs": ["u2"]},
          {"id": "A1", "scheme": 2, "refs": ["u3"]}], ()),
        ("a unit written after the last anchor",
         [{"id": "u1", "scheme": 0, "refs": []},
          {"id": "A1", "scheme": 2, "refs": ["u1"]},
          {"id": "u2", "scheme": 0, "refs": ["A1"]}], ()),
        ("a forged branch: units no scheme-2 event names",
         [{"id": "u1", "scheme": 0, "refs": []},
          {"id": "A1", "scheme": 2, "refs": ["u1"]},
          {"id": "f1", "scheme": 0, "refs": ["u1"]},
          {"id": "f2", "scheme": 0, "refs": ["f1"]}], ()),
        ("a unit this verifier held before its sunset",
         [{"id": "u1", "scheme": 0, "refs": []},
          {"id": "u2", "scheme": 0, "refs": ["u1"]}], ("u1",)),
    ]
    coverage_vectors = []
    for description, events, held in graphs:
        coverage_vectors.append({
            "name": description,
            "events": events,
            "held_before_sunset": list(held),
            "before_sunset": coverage(events, False, held),
            "after_sunset": coverage(events, True, held),
        })

    kind_policy = [
        {"kind": kind, "code": KIND_CODES[kind] if kind != "ignorable" else "64 to 127",
         "accepted_before_sunset": list(allowed_schemes(kind, False)),
         "signed_before_sunset": signing_scheme(kind, False),
         "accepted_after_sunset": list(allowed_schemes(kind, True)),
         "scheme_0_after_sunset_only_if_covered": SCHEME_ED25519 in allowed_schemes(kind, True),
         "signed_after_sunset": signing_scheme(kind, True)}
        for kind in KINDS
    ] + [{"kind": "reserved", "code": 3, "refused": "Malformed"},
         {"kind": "not yet defined", "code": "7 to 63",
          "note": "states its schemes when it is defined; one that decides authority takes "
                  "scheme 2 only"}]
    return {
        "kind_policy": kind_policy,
        "signers": [{"name": s_.name, "ed25519_seed": h(s_.ed_seed),
                     "ed25519_public": h(s_.ed_public), "mldsa_seed": h(s_.mldsa_seed),
                     "mldsa_public": h(s_.mldsa_public), "xwing_seed": h(s_.xwing_seed),
                     "xwing_public": h(s_.xwing_public), "kc": h(s_.kc),
                     "device_id": h(s_.device_id)} for s_ in (laptop, phone)],
        "signatures": signatures,
        "signature_refusals": negative,
        "coverage": coverage_vectors,
    }


def mldsa65_known_answers() -> dict:
    """crypto.json's mldsa65_known_answers: the vendored subset of
    Wycheproof's ML-DSA-65 tests, with this script's verdict on each."""
    import json

    kats = json.loads(mldsa.KATS.read_text())
    x = bytes.fromhex
    sign_groups = []
    for group in kats["sign"]:
        pk, sk = mldsa.mldsa_keygen(x(group["privateSeed"]))
        tests = []
        for case in group["tests"]:
            row = dict(case)
            if case["result"] == "invalid":
                try:
                    mldsa.message_prime(x(case["msg"]), x(case["ctx"]))
                    row["frasil"] = "accepted"
                except ValueError:
                    row["frasil"] = "refused"
            else:
                rnd = x(case["rnd"]) if "rnd" in case else bytes(32)
                mu = (mldsa.mu_of(pk, mldsa.message_prime(x(case["msg"]), x(case.get("ctx", ""))))
                      if "msg" in case else x(case["mu"]))
                row["frasil"] = ("signature matches" if mldsa.sign_mu(sk, mu, rnd).hex()
                                 == case["sig"] else "signature differs")
            tests.append(row)
        sign_groups.append({**{k: v for k, v in group.items() if k != "tests"},
                            "public_key_matches": pk.hex() == group["publicKey"], "tests": tests})
    verify_groups = []
    for group in kats["verify"]:
        pk = x(group["publicKey"])
        tests = []
        for case in group["tests"]:
            ok = mldsa.mldsa_verify(pk, x(case["msg"]), x(case["sig"]), x(case.get("ctx", "")))
            tests.append({**case, "frasil": "valid" if ok else "invalid"})
        verify_groups.append({**{k: v for k, v in group.items() if k != "tests"}, "tests": tests})
    return {"source": kats["source"], "sign": sign_groups, "verify": verify_groups}


def self_test() -> None:
    mldsa.self_test()
    # A round trip, determinism, and each half checked on its own.
    laptop = device_signer("laptop")
    tbs = build_event(laptop, "space", b"self-test")["tbs"]
    sig = sign(laptop, SCHEME_HYBRID, tbs)
    assert sig == sign(laptop, SCHEME_HYBRID, tbs), "scheme 2 is not deterministic"
    assert len(sig) == HYBRID_SIGNATURE_BYTES == 3373
    verify("space", SCHEME_HYBRID, laptop.ed_public, laptop.kc, tbs, sig, keys=[laptop.keys])
    assert _expect(verify, "space", SCHEME_HYBRID, laptop.ed_public, laptop.kc, tbs + b"x", sig,
                   keys=[laptop.keys]) == "BadSignature"
    # The Ed25519 half of a scheme-2 signature never verifies as scheme 0,
    # and verifies with the author key alone.
    assert not ed25519_verify_strict(laptop.ed_public, tbs, sig[:64])
    assert verify_ed25519_half(laptop.ed_public, tbs, sig)
    assert verify_mldsa_half(laptop.ed_public, laptop.mldsa_public, tbs, sig)
    assert _expect(verify, "space", SCHEME_HYBRID, laptop.ed_public, laptop.kc, tbs,
                   bytes([sig[0] ^ 1]) + sig[1:], keys=[]) == "BadSignature"
    assert _expect(verify, "space", SCHEME_HYBRID, laptop.ed_public, laptop.kc, tbs, sig,
                   keys=[]) == "NoHybridKey"
    # Coverage: a forged branch stays out after the sunset.
    events = [{"id": "u1", "scheme": 0, "refs": []}, {"id": "A", "scheme": 2, "refs": ["u1"]},
              {"id": "f", "scheme": 0, "refs": ["u1"]}]
    assert coverage(events, True) == {"u1": "accepted", "A": "accepted", "f": "Uncovered"}
    v = signature_vectors()
    refusals = {c["name"]: c["expected"] for c in v["signature_refusals"]}
    assert refusals["an Ed25519 half whose S is not reduced"] == "BadSignature"
    assert refusals["an Ed25519 half whose R is of small order"] == "BadSignature"
    assert refusals["a scheme-0 unit after the sunset, not covered"] == "Uncovered"
    assert refusals["a scheme-0 unit before the sunset, covered"] == "accepted"
    assert refusals["no ML-DSA-65 key held"] == "NoHybridKey"
    assert refusals["an ML-DSA-65 key held whose hash, with its X-Wing key, is not the "
                    "signer's kc: another device's"] == "NoHybridKey"
    assert refusals["a forgery that reuses the laptop's Ed25519 key under a kc of its own: "
                    "accepted, as another device ID"] == "accepted"
    assert refusals["the same forger's event under the laptop's own kc"] == "BadSignature"
    k = mldsa65_known_answers()
    assert all(t["frasil"] in ("signature matches", "refused") for g in k["sign"]
               for t in g["tests"])
    assert all(t["frasil"] == t["result"] for g in k["verify"] for t in g["tests"])


if __name__ == "__main__":
    self_test()
    print("ok")
