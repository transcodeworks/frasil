//! Properties of the key checks and the wrap on arbitrary input.
#![cfg(not(target_arch = "wasm32"))]

use frasil_base::ErrorClass;
use frasil_crypto::keys::{self, Ed25519Step, X25519Step};
use frasil_crypto::wrap::{self, WrapLength, WrapUse};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The first failing step is the first false one of the steps taken on
    /// their own, in the document's order.
    #[test]
    fn ed25519_check_agrees_with_its_steps(key in proptest::collection::vec(any::<u8>(), 30..34)) {
        let steps = keys::ed25519_steps(&key);
        let expected = if !steps.length_ok {
            Err(Ed25519Step::LengthOk)
        } else if !steps.decodes {
            Err(Ed25519Step::Decodes)
        } else if !steps.canonical {
            Err(Ed25519Step::Canonical)
        } else if steps.small_order == Some(true) {
            Err(Ed25519Step::SmallOrder)
        } else if steps.torsion_free == Some(false) {
            Err(Ed25519Step::TorsionFree)
        } else {
            Ok(())
        };
        prop_assert_eq!(keys::check_ed25519(&key), expected);
    }

    #[test]
    fn x25519_check_agrees_with_its_steps(key in proptest::collection::vec(any::<u8>(), 31..34)) {
        let expected = match keys::x25519_steps(&key) {
            None => Err(X25519Step::LengthOk),
            Some(steps) if !steps.top_bit_clear => Err(X25519Step::TopBitClear),
            Some(steps) if !steps.below_p => Err(X25519Step::BelowP),
            Some(steps) if !steps.prime_order => Err(X25519Step::PrimeOrder),
            Some(_) => Ok(()),
        };
        prop_assert_eq!(keys::check_x25519(&key), expected);
    }

    /// An honest X25519 key passes, and so does the X-Wing key of any seed.
    #[test]
    fn honest_keys_pass(seed in any::<[u8; 32]>()) {
        let x25519 = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed));
        prop_assert_eq!(keys::check_x25519(x25519.as_bytes()), Ok(()));
        prop_assert_eq!(keys::xwing_valid(&wrap::xwing_public(&seed)), Ok(()));
    }

    /// A wrap opens to its plaintext under its seed and info, and a change
    /// to any byte makes it fail.
    #[test]
    fn a_wrap_round_trips_and_any_change_refuses_it(
        seed in any::<[u8; 32]>(),
        randomness in proptest::collection::vec(any::<u8>(), 64),
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
        flip in any::<prop::sample::Index>(),
    ) {
        let info = WrapUse::ExchangeMessage.info(b"request");
        let length = WrapUse::ExchangeMessage.length();
        let randomness: [u8; 64] = randomness.try_into().unwrap();
        let sealed = wrap::seal_wrap_with(&wrap::xwing_public(&seed), &info, &plaintext, &randomness).unwrap();
        let opened = wrap::open_wrap(&sealed, &seed, &info, length).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
        let mut changed = sealed.clone();
        changed[flip.index(sealed.len())] ^= 1;
        prop_assert!(wrap::open_wrap(&changed, &seed, &info, length).is_err());
    }

    /// Reading a wrap's layout never panics, and gives the document's
    /// classes only.
    #[test]
    fn reading_any_bytes_as_a_wrap_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1300)) {
        match wrap::read_wrap(&bytes, WrapLength::AtLeast(0)) {
            Ok(parts) => prop_assert_eq!(parts.enc.len() + parts.ciphertext.len() + 3, bytes.len()),
            Err(class) => prop_assert!(matches!(class, ErrorClass::Malformed | ErrorClass::UnsupportedVersion)),
        }
    }
}
