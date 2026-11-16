//! frasil-deposit-tokens' `TokenRequest` reader, and a peer's checks of a
//! request and issuing, on arbitrary bytes (ext-deposit-tokens.md, 2.5
//! Messages and 3.4 Issuing). They never panic; what the reader accepts is
//! the one encoding of what it returns; the checks refuse only with their
//! steps' classes; and a batch issued is at most what was sent and what
//! the allowance and share leave.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor;
use frasil_base::time::Reading;
use frasil_deposit_tokens::peer::Window;
use frasil_deposit_tokens::rotation::LiveKey;
use frasil_deposit_tokens::settings::{DepositSettings, TOKEN_PERIOD};
use frasil_deposit_tokens::{
    DepositKey, IssuanceRecords, KeyShard, TokenClass, TokenRequest, check_request, issue_with,
};
use frasil_libraries::{Issuer, LibraryId, LibraryState, PeerRecords, TicketId, TrustedIssuers};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A peer with one key, one trusted issuer, a library open and one
/// suspended, and spaces whose first byte says their library.
struct Records;

impl PeerRecords for Records {
    fn ticket_used(&self, id: &TicketId) -> bool {
        id[0] & 1 == 1
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        library
            .as_str()
            .starts_with('s')
            .then_some(LibraryState::Suspended)
    }

    fn deposit_tokens(&self) -> bool {
        true
    }
}

impl IssuanceRecords for Records {
    fn space_library(&self, space: &[u8; 32]) -> Option<LibraryId> {
        match space[0] % 3 {
            0 => None,
            1 => LibraryId::new("open").ok(),
            _ => LibraryId::new("suspended").ok(),
        }
    }

    fn deposit_settings(&self, _: &LibraryId) -> DepositSettings {
        DepositSettings {
            deposit_allowance: 20,
            space_share: 5,
        }
    }

    fn window(&self, _: &LibraryId) -> Option<Window> {
        Some(Window {
            start: 0,
            drawn: 12,
        })
    }

    fn space_drawn(&self, _: &LibraryId, space: &[u8; 32]) -> u64 {
        u64::from(space[1] % 8)
    }
}

fn peer() -> &'static (KeyShard, TrustedIssuers) {
    static PEER: OnceLock<(KeyShard, TrustedIssuers)> = OnceLock::new();
    PEER.get_or_init(|| {
        let began = Reading {
            timeline: 0,
            wall: None,
            run: 1,
        };
        let key = DepositKey::from_seed(&[7; 32]);
        let keys = KeyShard::from_keys(TOKEN_PERIOD, vec![LiveKey { key, began }]).unwrap();
        let issuer = Issuer::from_seed(&[1; 32]);
        (keys, TrustedIssuers::new([*issuer.public()]).unwrap())
    })
}

fuzz_target!(|data: &[u8]| {
    let read = TokenRequest::decode(data);
    if let Ok(request) = &read {
        assert_eq!(request.encode(), data, "a second encoding of TokenRequest");
    }
    let Ok(value) = cbor::decode(data) else {
        return;
    };
    let Ok(map) = value.as_map() else {
        return;
    };
    let (keys, issuers) = peer();
    let store = |space: &[u8; 32]| space[2] & 1 == 0;
    match check_request(map, store, Some(1_000), 60, issuers, keys, &Records) {
        Ok(approved) => {
            assert!(read.is_ok());
            assert!(approved.count >= 1 && approved.count <= approved.blinded.len());
            assert!(approved.count <= 8);
            let issued = issue_with(&approved, keys.issuing().unwrap(), &[3; 32]).unwrap();
            assert_eq!(issued.answer.evaluated.len(), approved.count);
            assert!(issued.window.drawn <= 20);
        }
        Err(class) => assert!(
            matches!(
                class,
                TokenClass::Shared(ErrorClass::Malformed)
                    | TokenClass::TicketRefused
                    | TokenClass::TicketExpired
                    | TokenClass::TicketUsed
                    | TokenClass::LibraryClosed
                    | TokenClass::NoLibrary
                    | TokenClass::CredentialRefused
                    | TokenClass::TokenExpired
                    | TokenClass::AllowanceExhausted
            ),
            "{class:?}"
        ),
    }
});
