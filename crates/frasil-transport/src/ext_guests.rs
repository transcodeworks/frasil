//! The leave request as a device mailbox item (ext-guests.md, "Names,
//! labels and error classes" and "A leave request", feature `ext-guests`).
//!
//! The leaver seals one item to each administering device's mailbox under
//! the content name `frasil/leave-request`; a core implementation drops it
//! (`UnknownContent`), and with this feature
//! [`content::implemented`](crate::mailbox::content::implemented) accepts
//! it. The body, the signed request, is `frasil-admission`'s.

use crate::TransportClass;
use crate::mailbox::seal_item_with;
use frasil_crypto::device::DeviceKeys;
use frasil_crypto::wrap::ENCAPSULATION_RANDOMNESS;

pub use crate::mailbox::content::LEAVE_REQUEST;

/// Seals a signed leave request as an item for one administering device,
/// to the X-Wing key its device ID commits to, with the wrap's
/// encapsulation randomness.
///
/// # Errors
///
/// As [`seal_item_with`].
pub fn seal_leave_item_with(
    signed: &[u8],
    recipient: &DeviceKeys,
    randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, TransportClass> {
    seal_item_with(LEAVE_REQUEST, signed, recipient, randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::content;

    #[test]
    fn the_name_is_implemented() {
        assert!(content::implemented(LEAVE_REQUEST));
        assert!(content::implemented(content::ACCESS_REQUEST));
        assert!(!content::implemented("app/other"));
    }
}
