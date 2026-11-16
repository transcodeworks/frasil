//! `crypto.json`: the labels, sizes and suites, the key checks, the test
//! fixtures and the X-Wing wrap (crypto.md, sections 2.1 to 2.4, 2.6 and 3.1
//! to 3.5).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use frasil_base::errors::{Class, ErrorClass};
use frasil_base::notation::field;
use frasil_crypto::device::{DeviceKeys, HybridKeys, IdentityKey, device_id, keys_commitment};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::keys::{self, Ed25519Step, X25519Step};
use frasil_crypto::labels::DEVICE_KEYS_COMMITMENT;
use frasil_crypto::primitives::sha256;
use frasil_crypto::wrap::{self, WrapLength, WrapUse};
use frasil_crypto::{labels, sizes};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;
use serde_json::Value;

const FILE: &str = "crypto.json";

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("a value of the expected length")
}

fn class(name: &str) -> ErrorClass {
    ErrorClass::from_name(name).unwrap_or_else(|| panic!("no class {name}"))
}

// ---------------------------------------------------------------------------
// labels

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Labels {
    registry: Vec<RegistryRow>,
    purpose_strings: Vec<PurposeRow>,
    reserved: Vec<ReservedRow>,
    other_names: Vec<String>,
    none_equals_or_prefixes_another: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryRow {
    label: String,
    #[serde(deserialize_with = "hex::bytes")]
    hex: Vec<u8>,
    used_as: String,
    #[serde(rename = "in")]
    document: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeRow {
    string: String,
    #[serde(deserialize_with = "hex::bytes")]
    hex: Vec<u8>,
    #[serde(rename = "use")]
    used_as: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservedRow {
    string: String,
    #[serde(deserialize_with = "hex::bytes")]
    hex: Vec<u8>,
}

#[test]
fn labels() {
    let rows: Labels = vectors::family(FILE, "labels");
    assert_eq!(rows.registry.len(), labels::REGISTRY.len());
    for (row, label) in rows.registry.iter().zip(labels::REGISTRY) {
        assert_eq!(row.label.as_bytes(), row.hex, "{}", row.label);
        assert_eq!(label.bytes, row.hex, "{}", row.label);
        assert_eq!(label.used_as, row.used_as, "{}", row.label);
        assert_eq!(label.document, row.document, "{}", row.label);
    }
    assert_eq!(rows.purpose_strings.len(), labels::PURPOSE_STRINGS.len());
    for (row, purpose) in rows.purpose_strings.iter().zip(labels::PURPOSE_STRINGS) {
        assert_eq!(row.string.as_bytes(), row.hex);
        assert_eq!(purpose.bytes, row.hex);
        assert_eq!(purpose.used_as, row.used_as);
    }
    assert_eq!(rows.reserved.len(), labels::RESERVED.len());
    for (row, reserved) in rows.reserved.iter().zip(labels::RESERVED) {
        assert_eq!(row.string.as_bytes(), row.hex);
        assert_eq!(*reserved, row.hex);
    }
    assert_eq!(rows.other_names, labels::OTHER_NAMES);
    assert!(rows.none_equals_or_prefixes_another);
    assert!(labels::clashes().is_empty());
}

// ---------------------------------------------------------------------------
// sizes, suites, wrap_uses, constants

#[test]
fn sizes() {
    let rows: std::collections::BTreeMap<String, usize> = vectors::family(FILE, "sizes");
    let ours = [
        ("ed25519_seed", sizes::ED25519_SEED),
        ("ed25519_public", sizes::ED25519_PUBLIC),
        ("ed25519_signature", sizes::ED25519_SIGNATURE),
        ("xwing_seed", sizes::XWING_SEED),
        ("xwing_public", sizes::XWING_PUBLIC),
        ("xwing_enc", sizes::XWING_ENC),
        ("mldsa65_seed", sizes::MLDSA65_SEED),
        ("mldsa65_public", sizes::MLDSA65_PUBLIC),
        ("mldsa65_secret_expanded", sizes::MLDSA65_SECRET_EXPANDED),
        ("mldsa65_signature", sizes::MLDSA65_SIGNATURE),
        ("scheme2_signature", sizes::SCHEME2_SIGNATURE),
        ("xchacha20poly1305_nonce", sizes::XCHACHA20POLY1305_NONCE),
        ("xchacha20poly1305_tag", sizes::XCHACHA20POLY1305_TAG),
    ];
    assert_eq!(rows.len(), ours.len());
    for (name, size) in ours {
        assert_eq!(rows.get(name), Some(&size), "{name}");
    }
    // The implementations agree.
    let key = frasil_crypto::mldsa65::Mldsa65Key::from_seed(&[1; 32]);
    assert_eq!(key.public().len(), sizes::MLDSA65_PUBLIC);
    assert_eq!(key.sign(b"").len(), sizes::MLDSA65_SIGNATURE);
    let expanded = ml_dsa_expanded_bytes();
    assert_eq!(expanded, sizes::MLDSA65_SECRET_EXPANDED);
    assert_eq!(wrap::xwing_public(&[1; 32]).len(), sizes::XWING_PUBLIC);
}

/// The length of an expanded ML-DSA-65 secret key, as the implementation
/// encodes it.
fn ml_dsa_expanded_bytes() -> usize {
    use ml_dsa::{ExpandedSigningKey, MlDsa65};
    #[allow(deprecated)]
    let bytes = ExpandedSigningKey::<MlDsa65>::from_seed(&[1; 32].into()).to_expanded();
    bytes.len()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiteRow {
    name: String,
    kem: u16,
    kdf: Option<u16>,
    aead: Option<u16>,
    state: String,
}

#[test]
fn suites() {
    let rows: Vec<SuiteRow> = vectors::family(FILE, "suites");
    assert_eq!(rows.len(), 2);
    let xwing = &rows[0];
    assert_eq!(xwing.name, "X-Wing (MLKEM768-X25519)");
    assert_eq!(xwing.kem, wrap::SUITE_XWING);
    assert_eq!(xwing.kdf, Some(wrap::KDF_HKDF_SHA256));
    assert_eq!(xwing.aead, Some(wrap::AEAD_CHACHA20POLY1305));
    assert_eq!(xwing.state, "the only suite");
    let x25519 = &rows[1];
    assert_eq!(x25519.kem, wrap::SUITE_X25519);
    assert_eq!((x25519.kdf, x25519.aead), (None, None));
    assert_eq!(x25519.state, "refused: UnsupportedVersion");
    // A wrap naming it is refused as UnsupportedVersion, before its length.
    let mut wrap = vec![wrap::WRAP_VERSION];
    wrap.extend_from_slice(&x25519.kem.to_be_bytes());
    assert_eq!(
        wrap::read_wrap(&wrap, WrapLength::AtLeast(0)),
        Err(ErrorClass::UnsupportedVersion)
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapUseRow {
    #[serde(rename = "use")]
    name: String,
    label: String,
    length: Value,
}

#[test]
fn wrap_uses() {
    let rows: Vec<WrapUseRow> = vectors::family(FILE, "wrap_uses");
    assert_eq!(rows.len(), WrapUse::ALL.len());
    let names = [
        "bundle wrap",
        "space wrap",
        "removal wrap",
        "slot token",
        "exchange message",
        "welcome",
        "device mailbox item",
    ];
    for ((row, ours), name) in rows.iter().zip(WrapUse::ALL).zip(names) {
        assert_eq!(row.name, name);
        assert_eq!(row.label.as_bytes(), ours.label(), "{name}");
        let length = match &row.length {
            Value::Number(n) => WrapLength::Exactly(n.as_u64().unwrap() as usize),
            Value::String(text) => {
                let numbers: Vec<usize> = text
                    .replace(',', "")
                    .split(' ')
                    .filter_map(|word| word.parse().ok())
                    .collect();
                match (text.starts_with("at least"), numbers.as_slice()) {
                    (true, [minimum]) => WrapLength::AtLeast(*minimum),
                    (false, [minimum, maximum]) => WrapLength::Between(*minimum, *maximum),
                    _ => panic!("{name}: a length {text:?}"),
                }
            }
            other => panic!("{name}: a length {other}"),
        };
        assert_eq!(ours.length(), length, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Constants {
    p: String,
    l: String,
    d: String,
}

/// A big-endian hex integer as 32 little-endian bytes.
fn little_endian(text: &str) -> [u8; 32] {
    let mut bytes = hex::decode(&format!("{text:0>64}")).unwrap();
    bytes.reverse();
    array(&bytes)
}

#[test]
fn constants() {
    let rows: Constants = vectors::family(FILE, "constants");
    assert_eq!(little_endian(&rows.p), keys::P);
    assert_eq!(little_endian(&rows.l), keys::L);
    assert_eq!(little_endian(&rows.d), keys::D);
}

// ---------------------------------------------------------------------------
// ed25519_keys, x25519_keys, x25519_at_use, xwing_keys

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519Row {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    key: Vec<u8>,
    decodes: bool,
    canonical: bool,
    small_order: Option<bool>,
    torsion_free: Option<bool>,
    accepted_by_a_lenient_decoder: bool,
    result: String,
    refused_at: Option<String>,
}

#[test]
fn ed25519_keys() {
    let rows: Vec<Ed25519Row> = vectors::family(FILE, "ed25519_keys");
    assert_eq!(rows.len(), 43);
    for row in &rows {
        let name = &row.name;
        let verdict = keys::check_ed25519(&row.key);
        assert_eq!(
            verdict.err().map(Ed25519Step::name),
            row.refused_at.as_deref(),
            "{name}"
        );
        assert_eq!(verdict.is_ok(), row.result == "accept", "{name}");
        assert_eq!(
            keys::ed25519_valid(&row.key),
            if row.result == "accept" {
                Ok(())
            } else {
                Err(ErrorClass::InvalidKey)
            },
            "{name}"
        );
        let steps = keys::ed25519_steps(&row.key);
        assert_eq!(steps.length_ok, row.key.len() == 32, "{name}");
        assert_eq!(steps.decodes, row.decodes, "{name}");
        assert_eq!(steps.canonical, row.canonical, "{name}");
        assert_eq!(steps.small_order, row.small_order, "{name}");
        assert_eq!(steps.torsion_free, row.torsion_free, "{name}");
        // What a lenient decoder, curve25519-dalek's, would accept.
        let lenient = <[u8; 32]>::try_from(row.key.as_slice())
            .is_ok_and(|bytes| CompressedEdwardsY(bytes).decompress().is_some());
        assert_eq!(lenient, row.accepted_by_a_lenient_decoder, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X25519Row {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    key: Vec<u8>,
    top_bit_clear: Option<bool>,
    below_p: Option<bool>,
    on_curve: Option<bool>,
    prime_order: Option<bool>,
    result: String,
    refused_at: Option<String>,
}

#[test]
fn x25519_keys() {
    let rows: Vec<X25519Row> = vectors::family(FILE, "x25519_keys");
    assert_eq!(rows.len(), 18);
    for row in &rows {
        let name = &row.name;
        let verdict = keys::check_x25519(&row.key);
        assert_eq!(
            verdict.err().map(X25519Step::name),
            row.refused_at.as_deref(),
            "{name}"
        );
        assert_eq!(verdict.is_ok(), row.result == "accept", "{name}");
        assert_eq!(
            keys::x25519_valid(&row.key).is_ok(),
            row.result == "accept",
            "{name}"
        );
        let steps = keys::x25519_steps(&row.key);
        assert_eq!(steps.map(|s| s.top_bit_clear), row.top_bit_clear, "{name}");
        assert_eq!(steps.map(|s| s.below_p), row.below_p, "{name}");
        assert_eq!(steps.map(|s| s.prime_order), row.prime_order, "{name}");
        // Whether u, reduced, is on the curve rather than its twist: the
        // Montgomery-to-Edwards map exists exactly then.
        let on_curve = <[u8; 32]>::try_from(row.key.as_slice()).ok().map(|mut u| {
            u[31] &= 0x7f;
            MontgomeryPoint(u).to_edwards(0).is_some()
        });
        assert_eq!(on_curve, row.on_curve, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtUseRow {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    private: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    public: Vec<u8>,
    #[serde(default, deserialize_with = "optional_hex")]
    shared: Option<Vec<u8>>,
    error: Option<String>,
}

fn optional_hex<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|text| hex::decode(&text).map_err(serde::de::Error::custom))
        .transpose()
}

#[test]
fn x25519_at_use() {
    let rows: Vec<AtUseRow> = vectors::family(FILE, "x25519_at_use");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        let result = keys::x25519_at_use(&array(&row.private), &array(&row.public));
        match (&row.shared, &row.error) {
            (Some(shared), None) => {
                assert_eq!(
                    result.unwrap().as_slice(),
                    shared.as_slice(),
                    "{}",
                    row.name
                )
            }
            (None, Some(error)) => assert_eq!(result, Err(class(error)), "{}", row.name),
            _ => panic!("{}: a shared secret or an error", row.name),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XWingKeyRow {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    key: Vec<u8>,
    result: String,
}

#[test]
fn xwing_keys() {
    let rows: Vec<XWingKeyRow> = vectors::family(FILE, "xwing_keys");
    assert_eq!(rows.len(), 5);
    for row in &rows {
        let expected = match row.result.as_str() {
            "accept" => Ok(()),
            "refuse" => Err(ErrorClass::InvalidKey),
            other => panic!("{}: a result {other}", row.name),
        };
        assert_eq!(keys::xwing_valid(&row.key), expected, "{}", row.name);
    }
}

// ---------------------------------------------------------------------------
// fixtures

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRow {
    #[serde(deserialize_with = "hex::bytes")]
    identity_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    identity: Vec<u8>,
    #[serde(default, deserialize_with = "optional_hex")]
    xwing_seed: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    xwing: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    kc: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    device_id: Vec<u8>,
}

#[test]
fn fixtures() {
    let rows: std::collections::BTreeMap<String, FixtureRow> = vectors::family(FILE, "fixtures");
    assert_eq!(
        rows.keys().map(String::as_str).collect::<Vec<_>>(),
        ["laptop", "phone", "recovery_agent"]
    );
    for (name, row) in &rows {
        let keys = FixtureKeys::from_identity_seed(&array(&row.identity_seed));
        assert_eq!(keys.identity.as_slice(), row.identity, "{name}");
        assert_eq!(keys.mldsa_seed.as_slice(), row.mldsa_seed, "{name}");
        assert_eq!(keys.mldsa_public.as_slice(), row.mldsa_public, "{name}");
        assert_eq!(keys::ed25519_valid(&keys.identity), Ok(()), "{name}");
        assert_eq!(keys::mldsa_valid(keys.mldsa_public.as_slice()), Ok(()));
        let device = match (&row.xwing_seed, &row.xwing) {
            (Some(xwing_seed), Some(xwing)) => {
                assert_eq!(keys.xwing_seed.as_slice(), xwing_seed, "{name}");
                assert_eq!(keys.xwing.as_slice(), xwing, "{name}");
                assert_eq!(keys::xwing_valid(keys.xwing.as_slice()), Ok(()), "{name}");
                keys.device_keys()
            }
            // A recovery agent: the fixture's Ed25519 and ML-DSA-65 keys, and
            // no X-Wing key.
            (None, None) => DeviceKeys {
                ed: IdentityKey(keys.identity),
                keys: HybridKeys::new(keys.mldsa_public.as_slice(), None).unwrap(),
            },
            _ => panic!("{name}: an X-Wing seed and key, or neither"),
        };
        assert_eq!(device.keys.commitment().0.as_slice(), row.kc, "{name}");
        assert_eq!(device.device_id().0.as_slice(), row.device_id, "{name}");
    }
}

// ---------------------------------------------------------------------------
// device_ids

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceIds {
    labels: DeviceIdLabels,
    cases: Vec<DeviceIdCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceIdLabels {
    kc: String,
    device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceIdCase {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    ed25519_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_public: Vec<u8>,
    #[serde(default, deserialize_with = "optional_hex")]
    xwing_public: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    kc_input: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex::bytes")]
    kc: Vec<u8>,
    #[serde(default, deserialize_with = "optional_hex")]
    device_id_input: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex::bytes")]
    device_id: Vec<u8>,
}

#[test]
fn device_ids() {
    let family: DeviceIds = vectors::family(FILE, "device_ids");
    assert_eq!(family.labels.kc.as_bytes(), DEVICE_KEYS_COMMITMENT);
    assert_eq!(family.labels.device_id.as_bytes(), labels::DEVICE_ID);
    assert_eq!(family.cases.len(), 4);
    let mut ids = Vec::new();
    for case in &family.cases {
        let name = &case.name;
        let ed = IdentityKey(array(&case.ed25519_public));
        assert_eq!(keys::ed25519_valid(&ed.0), Ok(()), "{name}");
        let held = HybridKeys::new(&case.mldsa_public, case.xwing_public.as_deref()).unwrap();
        let kc = keys_commitment(&case.mldsa_public, case.xwing_public.as_deref());
        assert_eq!(&kc, held.commitment(), "{name}");
        assert_eq!(kc.0.as_slice(), case.kc, "{name}");
        if let Some(input) = &case.kc_input {
            // field(xwing) is u32be(0) for a holder with none.
            let mut expected = DEVICE_KEYS_COMMITMENT.to_vec();
            expected.extend_from_slice(&field(&case.mldsa_public));
            expected.extend_from_slice(&field(case.xwing_public.as_deref().unwrap_or_default()));
            assert_eq!(&expected, input, "{name}");
            assert_eq!(sha256(&[input]).as_slice(), case.kc, "{name}");
        }
        let id = device_id(&ed, &kc);
        assert_eq!(id.0.as_slice(), case.device_id, "{name}");
        if let Some(input) = &case.device_id_input {
            assert_eq!(&[labels::DEVICE_ID, &ed.0, &kc.0].concat(), input, "{name}");
            assert_eq!(sha256(&[input]).as_slice(), case.device_id, "{name}");
        }
        let device = DeviceKeys { ed, keys: held };
        assert_eq!(device.check(&id), Ok(()), "{name}");
        assert_eq!(device.signatory().device_id(), id, "{name}");
        ids.push((ed, id));
    }
    // The laptop's Ed25519 key beside the phone's other keys is another
    // device: one key, two device IDs.
    let (laptop, last) = (ids[0], ids[3]);
    assert_eq!(laptop.0, last.0);
    assert_ne!(laptop.1, last.1);
}

// ---------------------------------------------------------------------------
// wraps, wrap_refusals

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wraps {
    #[serde(deserialize_with = "hex::bytes")]
    space: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    key_name: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    content_key: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    bundle: Vec<u8>,
    recipients: Vec<Recipient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    identity: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    xwing_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    xwing: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    kc: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    device_id: Vec<u8>,
    derivation: String,
    #[serde(default, deserialize_with = "optional_hex")]
    prf_output: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    person_id: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    secret: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex::bytes")]
    encapsulation_randomness: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    info: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    enc: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    ciphertext: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    wrap: Vec<u8>,
    wrap_bytes: usize,
}

/// A bundle wrap's `info` binds the log, the key names, the grant's name
/// (empty for a device's wrap) and the recipient's device ID (keys.md,
/// "Bundle wraps").
fn bundle_wrap_info(log: &[u8], key_name: &[u8], recipient: &[u8]) -> Vec<u8> {
    let mut binds = field(log);
    binds.extend_from_slice(&field(key_name));
    binds.extend_from_slice(&field(b""));
    binds.extend_from_slice(recipient);
    WrapUse::BundleWrap.info(&binds)
}

#[test]
fn wraps() {
    let wraps: Wraps = vectors::family(FILE, "wraps");
    assert_eq!(wraps.recipients.len(), 4);
    // The bundle's content key follows its first byte (keys.md).
    assert_eq!(&wraps.bundle[1..33], wraps.content_key.as_slice());
    for r in &wraps.recipients {
        let name = &r.name;
        assert!(!r.derivation.is_empty());
        assert_eq!(
            wrap::xwing_public(&array(&r.xwing_seed)).as_slice(),
            r.xwing,
            "{name}"
        );
        assert_eq!(keys::xwing_valid(&r.xwing), Ok(()), "{name}");
        assert_eq!(keys::ed25519_valid(&r.identity), Ok(()), "{name}");
        if name == "a device" {
            // The fixture derivation, from the device's identity seed.
            assert!(r.prf_output.is_none() && r.person_id.is_none() && r.secret.is_none());
        }
        // The recipient's keys hash to the device ID the info binds.
        let device = DeviceKeys {
            ed: IdentityKey(array(&r.identity)),
            keys: HybridKeys::new(&r.mldsa_public, Some(&r.xwing)).unwrap(),
        };
        assert_eq!(device.keys.commitment().0.as_slice(), r.kc, "{name}");
        assert_eq!(device.device_id().0.as_slice(), r.device_id, "{name}");
        let info = bundle_wrap_info(&wraps.space, &wraps.key_name, &r.device_id);
        assert_eq!(info, r.info, "{name}");

        let randomness = array(&r.encapsulation_randomness);
        let (enc, ciphertext) =
            wrap::hpke_seal_with(&r.xwing, &r.info, b"", &wraps.bundle, &randomness).unwrap();
        assert_eq!(enc.as_slice(), r.enc, "{name}");
        assert_eq!(ciphertext, r.ciphertext, "{name}");
        let made = wrap::seal_wrap_with(&r.xwing, &r.info, &wraps.bundle, &randomness).unwrap();
        assert_eq!(made, r.wrap, "{name}");
        assert_eq!(made.len(), r.wrap_bytes, "{name}");

        let length = WrapUse::BundleWrap.length();
        assert!(length.admits(r.wrap_bytes));
        let opened = wrap::open_wrap(&r.wrap, &array(&r.xwing_seed), &r.info, length).unwrap();
        assert_eq!(opened.as_slice(), wraps.bundle, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapRefusal {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    wrap: Vec<u8>,
    opener: String,
    #[serde(deserialize_with = "hex::bytes")]
    log: Vec<u8>,
    error: String,
}

#[test]
fn wrap_refusals() {
    let wraps: Wraps = vectors::family(FILE, "wraps");
    let rows: Vec<WrapRefusal> = vectors::family(FILE, "wrap_refusals");
    assert_eq!(rows.len(), 8);
    for row in &rows {
        let opener = wraps
            .recipients
            .iter()
            .find(|r| r.name == row.opener)
            .unwrap_or_else(|| panic!("{}: no opener {}", row.name, row.opener));
        let info = bundle_wrap_info(&row.log, &wraps.key_name, &opener.device_id);
        let result = wrap::open_wrap(
            &row.wrap,
            &array(&opener.xwing_seed),
            &info,
            WrapUse::BundleWrap.length(),
        );
        let error = result.expect_err(&row.name);
        assert_eq!(error.name(), row.error, "{}", row.name);
    }
}
