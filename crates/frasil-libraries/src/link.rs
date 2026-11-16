//! A library ticket handed to a person as a link: the origin of the peer
//! that takes it, and the signed ticket's bytes, in the fragment so that a
//! browser that opens the link sends neither to any server.
//!
//! ```text
//! link     = origin "/#library-ticket=" base64url(signed ticket), without padding
//! origin   = ("https" / "http") "://" host [ ":" port ]
//! ```
//!
//! The ticket goes to the client as opaque bytes, as ext-libraries.md, 3.1
//! Getting a ticket, says: the link reads only its origin and its bytes, at
//! most 512 (section 2.2), and never the ticket. The origin is the peer to
//! connect to: the home peer an issuer names beside each ticket (section
//! 3.10), here the peer whose operator signed it.

use crate::LibraryClass;
use crate::ticket::MAX_TICKET_BYTES;
use frasil_base::ErrorClass;

/// What separates the origin from the ticket.
pub const MARKER: &str = "/#library-ticket=";

/// The longest origin a link carries, in bytes.
pub const MAX_ORIGIN_BYTES: usize = 2048;

/// A library ticket and the origin of the peer it is for.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketLink {
    origin: String,
    ticket: Vec<u8>,
}

impl core::fmt::Debug for TicketLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TicketLink")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl TicketLink {
    /// A link to `origin` carrying `ticket`.
    ///
    /// # Errors
    ///
    /// `Malformed` for an origin that is not `http` or `https` with a host
    /// and nothing after it, or a ticket of no byte or more than 512.
    pub fn new(origin: &str, ticket: &[u8]) -> Result<Self, LibraryClass> {
        check_origin(origin)?;
        if ticket.is_empty() || ticket.len() > MAX_TICKET_BYTES {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(Self {
            origin: origin.to_owned(),
            ticket: ticket.to_vec(),
        })
    }

    /// Reads a link's text, surrounding white space aside.
    ///
    /// # Errors
    ///
    /// `Malformed` for text of another shape, an origin as [`Self::new`]
    /// refuses it, or a fragment that is not canonical base64url of 1 to
    /// 512 bytes.
    pub fn parse(text: &str) -> Result<Self, LibraryClass> {
        let malformed = || LibraryClass::from(ErrorClass::Malformed);
        let (origin, encoded) = text.trim().split_once(MARKER).ok_or_else(malformed)?;
        if encoded.len() > MAX_TICKET_BYTES.div_ceil(3) * 4 {
            return Err(malformed());
        }
        let ticket = base64url::decode(encoded).ok_or_else(malformed)?;
        Self::new(origin, &ticket)
    }

    /// The origin of the peer the ticket is for, such as
    /// `https://peer.example.org`: where the device connects.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The signed ticket, as opaque bytes for the client.
    pub fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    /// The ticket's bytes, taking the link.
    pub fn into_ticket(self) -> Vec<u8> {
        self.ticket
    }
}

impl core::fmt::Display for TicketLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}{MARKER}{}",
            self.origin,
            base64url::encode(&self.ticket)
        )
    }
}

/// An origin: `http://` or `https://`, then a host and an optional port of
/// printable ASCII, with no path, query, fragment or credentials.
fn check_origin(origin: &str) -> Result<(), LibraryClass> {
    let malformed = || LibraryClass::from(ErrorClass::Malformed);
    if origin.len() > MAX_ORIGIN_BYTES {
        return Err(malformed());
    }
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(malformed)?;
    let printable = host
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && !b"/?#@\\".contains(&byte));
    if host.is_empty() || !printable {
        return Err(malformed());
    }
    Ok(())
}

/// base64url without padding (RFC 4648, section 5), as the link writes the
/// ticket: only [`encode`](base64url::encode)'s output decodes.
pub mod base64url {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encodes bytes, without padding.
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let n = u32::from_be_bytes([0, block[0], block[1], block[2]]);
            for i in 0..=chunk.len() {
                let index = (n >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            }
        }
        out
    }

    fn digit(c: u8) -> Option<u32> {
        ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
    }

    /// Decodes text without padding. `None` for a character outside the
    /// alphabet, a length that no byte string has, or unused bits that are
    /// not zero.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let text = text.as_bytes();
        if text.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
        for chunk in text.chunks(4) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= digit(c)? << (18 - 6 * i);
            }
            let bytes = n.to_be_bytes();
            let kept = chunk.len() - 1;
            out.extend_from_slice(&bytes[1..=kept]);
            if bytes[kept + 1..].iter().any(|&b| b != 0) {
                return None;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_carries_the_origin_and_the_bytes() {
        let ticket: Vec<u8> = (0..=200u8).collect();
        let link = TicketLink::new("https://peer.example.org", &ticket).unwrap();
        let text = link.to_string();
        assert!(text.starts_with("https://peer.example.org/#library-ticket="));
        let read = TicketLink::parse(&format!("  {text}\n")).unwrap();
        assert_eq!(read, link);
        assert_eq!(read.origin(), "https://peer.example.org");
        assert_eq!(read.ticket(), &ticket[..]);
        let local = TicketLink::new("http://127.0.0.1:8787", &[1, 2, 3]).unwrap();
        assert_eq!(
            local.to_string(),
            "http://127.0.0.1:8787/#library-ticket=AQID"
        );
        assert!(!format!("{local:?}").contains("AQID"));
    }

    #[test]
    fn other_shapes_are_refused() {
        let max = vec![7u8; MAX_TICKET_BYTES];
        assert!(TicketLink::new("https://p.example", &max).is_ok());
        for (origin, ticket) in [
            ("https://p.example", &[][..]),
            ("https://p.example", &[0u8; MAX_TICKET_BYTES + 1][..]),
            ("ftp://p.example", &[1][..]),
            ("https://", &[1][..]),
            ("https://p.example/path", &[1][..]),
            ("https://user@p.example", &[1][..]),
            ("https://p.example?x", &[1][..]),
            ("https://p example", &[1][..]),
        ] {
            assert!(TicketLink::new(origin, ticket).is_err(), "{origin}");
        }
        for text in [
            "https://p.example#library-ticket=AQID",
            "https://p.example/#library-ticket=",
            "https://p.example/#library-ticket=AQID=",
            "https://p.example/#library-ticket=AQJ",
            "https://p.example/#ticket=AQID",
            "AQID",
        ] {
            assert!(TicketLink::parse(text).is_err(), "{text}");
        }
    }
}
