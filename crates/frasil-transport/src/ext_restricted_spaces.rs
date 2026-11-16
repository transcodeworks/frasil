//! A restricted space on member connections (ext-restricted-spaces.md,
//! section 3.4, "Connections", feature `ext-restricted-spaces`).
//!
//! - A restricted space F's member key derives from F's own content secret
//!   `f(S_F)`, never from its parent's keys, so it does not move when the
//!   parent P rotates: `hk(S_F) = HKDF(none, f(S_F), "frasil/member-key/v1")`.
//!   The handshake is otherwise transport.md's, with F's states as the
//!   candidates.
//! - A device attaches F only on a connection where it has attached P. The
//!   roster check of an attach of F uses F's effective membership, which
//!   `frasil-space` narrows by P's.
//! - A device never announces F on a local network.

use crate::member::member_key;
use zeroize::Zeroizing;

/// `hk(S_F)` of a restricted space's state, from its own content secret
/// `f(S_F)`.
pub fn restricted_member_key(own_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    member_key(own_secret)
}

/// Whether a device may attach a restricted space on a connection: only
/// one where it has attached the space's parent. `parent_attached` says
/// whether this connection holds an admitted attach of the parent.
pub fn may_attach(parent_attached: bool) -> bool {
    parent_attached
}

/// Whether a device announces a space on a local network
/// (transport.md, "Member announcements"): never a restricted one.
pub fn announces(restricted: bool) -> bool {
    !restricted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_key_is_the_core_derivation_over_the_own_secret() {
        assert_eq!(*restricted_member_key(&[7; 32]), *member_key(&[7; 32]));
        assert!(!announces(true) && announces(false));
        assert!(may_attach(true) && !may_attach(false));
    }
}
