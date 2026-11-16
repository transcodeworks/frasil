//! frasil-space's roster-part reader on arbitrary bytes (roster.md, "The
//! roster part", "Changes" and "The event alone", steps 6 to 10): the bytes
//! as a genesis's roster part and as an update's or a checkpoint's, in an
//! event that rotates and one that does not. It never panics; it refuses
//! only with its document's classes, each where it can arise; and what it
//! accepts is the one encoding of what it returns, but for a genesis whose
//! descriptor a later document defines, of which it reads the kind alone.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_space::part::{PartContext, RosterPart};
use frasil_space::{Limits, SpaceClass};
use libfuzzer_sys::fuzz_target;

const AUTHOR: DeviceId = DeviceId([7; 32]);
const SPACE: [u8; 32] = [9; 32];

fuzz_target!(|data: &[u8]| {
    for space in [None, Some(&SPACE)] {
        for rotates in [false, true] {
            let context = PartContext {
                author: &AUTHOR,
                space,
                rotates,
                limits: &Limits::PROTOCOL,
            };
            match RosterPart::read(data, &context) {
                Ok(part) => {
                    let later = matches!(
                        &part,
                        RosterPart::Genesis(genesis) if genesis.descriptor.kind.is_reserved()
                    );
                    if !later {
                        assert_eq!(part.encode(), data, "a second encoding of a roster part");
                    }
                    assert_eq!(matches!(part, RosterPart::Genesis(_)), space.is_none());
                    // A checkpoint makes no change, and rotates.
                    let checkpoint = matches!(part, RosterPart::Checkpoint(_));
                    assert!(!checkpoint || (rotates && part.changes().is_empty()));
                    assert!(checkpoint || !part.changes().is_empty());
                    assert!(part.changes().len() <= 256);
                    assert!(part.changes().iter().filter(|c| c.grants_device()).count() <= 64);
                }
                Err(class) => {
                    let allowed = match class {
                        SpaceClass::Shared(shared) => {
                            matches!(
                                shared,
                                ErrorClass::Malformed
                                    | ErrorClass::UnsupportedVersion
                                    | ErrorClass::ExtensionRequired
                                    | ErrorClass::InvalidKey
                                    | ErrorClass::BadPossession
                            ) || (shared == ErrorClass::TooLarge && space.is_some())
                        }
                        SpaceClass::UnknownPolicy => space.is_none(),
                        SpaceClass::SelfRotation => space.is_some() && rotates,
                        SpaceClass::AdministerNotDevice => true,
                        _ => false,
                    };
                    assert!(allowed, "{class:?}");
                }
            }
        }
    }
});
