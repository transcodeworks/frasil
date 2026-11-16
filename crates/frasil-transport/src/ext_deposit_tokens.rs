//! ext-deposit-tokens.md's place in transport: message types 40 to 43,
//! service 6 and `MailboxPut` key 7 (transport.md, 2.4 Message types, 2.7
//! Mailboxes and 3.10 The device-to-peer handshake).
//!
//! The messages and the token are read by the extension's own crate; here
//! a receiver only turns them on. With the extension on,
//! [`MailboxPut::read`](crate::mailbox::MailboxPut::read) answers `Ok(None)`
//! for kind 3 with key 7, for the extension to read in its own order
//! (ext-deposit-tokens.md, 3.7 Redeeming). Without it, the types are
//! unknown and key 7 is `Malformed`, as at a core peer.

use crate::codes::Service;
use crate::frame::Extensions;

pub use crate::mailbox::TOKEN_KEY;

/// Service 6, `deposit`: a peer whose `PeerHello` lists it issues and takes
/// deposit tokens.
pub const SERVICE: Service = Service::Deposit;

/// The `Authorization` scheme of a token on the server binding's deposit
/// route: `Frasil-Token <258 lowercase hex>`.
pub const AUTHORIZATION_SCHEME: &str = "Frasil-Token";

/// A receiver's extensions with this one: it knows types 40 to 43 and
/// leaves `MailboxPut` key 7 to the extension.
pub const fn with_deposit_tokens(extensions: Extensions) -> Extensions {
    Extensions {
        deposit_tokens: true,
        ..extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::MessageType;

    #[test]
    fn the_types_are_known_only_with_the_extension() {
        let with = with_deposit_tokens(Extensions::NONE);
        for kind in [
            MessageType::TokenKeysGet,
            MessageType::TokenKeys,
            MessageType::TokenRequest,
            MessageType::TokenIssue,
        ] {
            assert!(kind.known_with(with));
            assert!(!kind.known_with(Extensions::NONE));
        }
        assert_eq!(SERVICE.code(), 6);
    }
}
