//! The statement and the shapes of its fields (ext-app-requests.md, "Terms
//! and limits", "The statement").
//!
//! ```text
//! statement =
//!      "frasil/device-signed-request/v1"     31 bytes
//!   || 0x01                                  version byte
//!   || 0x00                                  scheme byte: scheme 0, Ed25519
//!   || field(audience)                       4 + 8 to 256 bytes
//!   || field(subject)                        4 + 1 to 256 bytes
//!   || field(person_id)                      4 + 32 bytes
//!   || field(signer)                         4 + 64 bytes: ed || kc
//!   || field(method)                         4 + 1 to 16 bytes
//!   || field(path)                           4 + 1 to 2,048 bytes
//!   || field(query)                          4 + 0 to 2,048 bytes
//!   || field(SHA-256(body))                  4 + 32 bytes
//!   || u64be(expires_at)                     8 bytes
//!   || field(nonce)                          4 + 16 bytes
//!   || field(heads)                          4 + 32 × (0 to 16) bytes
//! ```
//!
//! A signer refuses to sign, and a verifier refuses, any value outside these
//! shapes, as `Malformed`.

use frasil_base::ErrorClass;
use frasil_base::notation::{push_field, text_ok, u64be};
use frasil_crypto::device::Signatory;
use frasil_crypto::labels::DEVICE_SIGNED_REQUEST;
use frasil_crypto::primitives::sha256;
use frasil_events::EventId;

/// The statement's label, `frasil/device-signed-request/v1`.
pub const LABEL: &[u8] = DEVICE_SIGNED_REQUEST;
/// The version byte, in the statement and in `X-Frasil-Signature`.
pub const VERSION: u8 = 0x01;
/// The scheme byte: scheme 0, Ed25519. A request is verified once, within
/// seconds, so it is scheme 0 (crypto.md); every other value is refused.
pub const SCHEME: u8 = 0x00;
/// Bytes of a nonce.
pub const NONCE_BYTES: usize = 16;
/// Bytes of a person ID and an event ID.
pub const ID_BYTES: usize = 32;
/// Bytes of a signer's `ed || kc`.
pub const SIGNER_BYTES: usize = 64;
/// The most heads a statement binds.
pub const MAX_HEADS: usize = 16;
/// The fewest bytes of an audience.
pub const MIN_AUDIENCE_BYTES: usize = 8;
/// The most bytes of an audience.
pub const MAX_AUDIENCE_BYTES: usize = 256;
/// The most bytes of a subject.
pub const MAX_SUBJECT_BYTES: usize = 256;
/// The most bytes of a method.
pub const MAX_METHOD_BYTES: usize = 16;
/// The most bytes of a path.
pub const MAX_PATH_BYTES: usize = 2048;
/// The most bytes of a query.
pub const MAX_QUERY_BYTES: usize = 2048;
/// The most bytes of a statement: every field at its limit.
pub const MAX_STATEMENT_BYTES: usize = LABEL.len()
    + 2
    + 4
    + MAX_AUDIENCE_BYTES
    + 4
    + MAX_SUBJECT_BYTES
    + 4
    + ID_BYTES
    + 4
    + SIGNER_BYTES
    + 4
    + MAX_METHOD_BYTES
    + 4
    + MAX_PATH_BYTES
    + 4
    + MAX_QUERY_BYTES
    + 4
    + 32
    + 8
    + 4
    + NONCE_BYTES
    + 4
    + ID_BYTES * MAX_HEADS;

/// The hosts `http` may name: loopback only.
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// What a request is about, as the signer sends it and as the verifier takes
/// it: from the verifier's configuration (the audience), the token (the
/// subject) and the request itself. None of it travels in a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// The verifier's origin in canonical form ([`audience_ok`]).
    pub audience: &'a str,
    /// The exact bytes of the token's subject (`sub`).
    pub subject: &'a [u8],
    /// The HTTP method, as the verifier receives it.
    pub method: &'a str,
    /// The request target's path exactly as sent, up to the first `?`.
    pub path: &'a str,
    /// The bytes after the first `?`, exactly as sent; empty without one.
    pub query: &'a str,
    /// The body exactly as sent; empty without one.
    pub body: &'a [u8],
}

impl<'a> Request<'a> {
    /// A request whose path and query come from its request target, split at
    /// the first `?` ([`split_target`]).
    pub fn from_target(
        audience: &'a str,
        subject: &'a [u8],
        method: &'a str,
        target: &'a str,
        body: &'a [u8],
    ) -> Self {
        let (path, query) = split_target(target);
        Self {
            audience,
            subject,
            method,
            path,
            query,
            body,
        }
    }
}

/// A request target's path and query: the path up to the first `?`, and the
/// bytes after it, or nothing without a `?`. A target that ends in `?` and
/// one without `?` give one statement.
pub fn split_target(target: &str) -> (&str, &str) {
    target.split_once('?').unwrap_or((target, ""))
}

/// Whether `audience` is the verifier's origin in canonical form: `scheme
/// "://" host`, then `":" port` only when the port is not the scheme's
/// default; 8 to 256 bytes.
///
/// - The scheme is `https`, or `http` when the host is `localhost`,
///   `127.0.0.1` or `[::1]`.
/// - The host is lower case: labels of `a` to `z`, `0` to `9` and `-`
///   joined by single dots, or an IPv6 address in brackets holding only `0`
///   to `9`, `a` to `f`, `:` and `.`.
/// - The port is 1 to 65,535 in decimal without a leading zero, and never
///   443 after `https` or 80 after `http`.
pub fn audience_ok(audience: &str) -> bool {
    if !(MIN_AUDIENCE_BYTES..=MAX_AUDIENCE_BYTES).contains(&audience.len()) {
        return false;
    }
    let (https, rest) = if let Some(rest) = audience.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = audience.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    let (host, after) = if rest.starts_with('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        let (host, after) = rest.split_at(close + 1);
        let inner = &host[1..host.len() - 1];
        let ipv6 = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b':' | b'.');
        if inner.is_empty() || !inner.bytes().all(ipv6) {
            return false;
        }
        (host, after)
    } else {
        let (host, after) = rest.split_at(rest.find(':').unwrap_or(rest.len()));
        let label = |label: &str| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        };
        if !host.split('.').all(label) {
            return false;
        }
        (host, after)
    };
    if !after.is_empty() {
        let Some(port) = after.strip_prefix(':') else {
            return false;
        };
        let default = if https { 443 } else { 80 };
        match decimal(port.as_bytes(), 5) {
            Some(number) if (1..=65_535).contains(&number) && number != default => {}
            _ => return false,
        }
    }
    https || LOOPBACK_HOSTS.contains(&host)
}

/// Whether `subject` is a token's subject: 1 to 256 bytes of UTF-8, with no
/// control character (Unicode category Cc) and not only white space.
pub fn subject_ok(subject: &[u8]) -> bool {
    core::str::from_utf8(subject).is_ok_and(|text| text_ok(text, MAX_SUBJECT_BYTES))
}

/// Whether `method` is 1 to 16 upper-case ASCII letters.
pub fn method_ok(method: &str) -> bool {
    (1..=MAX_METHOD_BYTES).contains(&method.len()) && method.bytes().all(|b| b.is_ascii_uppercase())
}

/// Whether `path` begins with `/`, holds 1 to 2,048 bytes from `0x21` to
/// `0x7e`, and holds no `?` or `#`.
pub fn path_ok(path: &str) -> bool {
    (1..=MAX_PATH_BYTES).contains(&path.len())
        && path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#')
}

/// Whether `query` holds 0 to 2,048 bytes from `0x21` to `0x7e`, with no
/// `#`.
pub fn query_ok(query: &str) -> bool {
    query.len() <= MAX_QUERY_BYTES && query.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
}

/// Whether `heads` are 0 to 16 event IDs, strictly ascending.
pub fn heads_ok(heads: &[EventId]) -> bool {
    heads.len() <= MAX_HEADS && heads.windows(2).all(|pair| pair[0] < pair[1])
}

/// Whether the audience, subject, method, path and query have their shapes
/// (the verifier's step 5).
pub fn request_ok(request: &Request<'_>) -> bool {
    audience_ok(request.audience)
        && subject_ok(request.subject)
        && method_ok(request.method)
        && path_ok(request.path)
        && query_ok(request.query)
}

/// 1 to `digits` decimal digits, with no leading zero unless the value is
/// `0`; `None` otherwise. At most 20 digits, so it never overflows `u128`.
pub(crate) fn decimal(text: &[u8], digits: usize) -> Option<u128> {
    if !(1..=digits.min(20)).contains(&text.len()) || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if text.len() > 1 && text[0] == b'0' {
        return None;
    }
    Some(
        text.iter()
            .fold(0u128, |n, &d| n * 10 + u128::from(d - b'0')),
    )
}

/// The statement, part by part, with each part's name as the vectors give
/// it: `label`, `version`, `scheme`, `audience`, `subject`, `person_id`,
/// `signer`, `method`, `path`, `query`, `body_hash`, `expires_at`,
/// `nonce` and `heads`.
///
/// # Errors
///
/// `Malformed` for an audience, subject, method, path, query or heads
/// outside its shape.
pub fn statement_parts(
    request: &Request<'_>,
    person_id: &[u8; 32],
    signer: &Signatory,
    expires_at: u64,
    nonce: &[u8; NONCE_BYTES],
    heads: &[EventId],
) -> Result<Vec<(&'static str, Vec<u8>)>, ErrorClass> {
    if !request_ok(request) || !heads_ok(heads) {
        return Err(ErrorClass::Malformed);
    }
    let field = |x: &[u8]| {
        let mut out = Vec::with_capacity(4 + x.len());
        push_field(&mut out, x);
        out
    };
    let joined: Vec<u8> = heads.iter().flat_map(|id| id.0).collect();
    Ok(vec![
        ("label", LABEL.to_vec()),
        ("version", vec![VERSION]),
        ("scheme", vec![SCHEME]),
        ("audience", field(request.audience.as_bytes())),
        ("subject", field(request.subject)),
        ("person_id", field(person_id)),
        ("signer", field(&signer.to_bytes())),
        ("method", field(request.method.as_bytes())),
        ("path", field(request.path.as_bytes())),
        ("query", field(request.query.as_bytes())),
        ("body_hash", field(&sha256(&[request.body]))),
        ("expires_at", u64be(expires_at).to_vec()),
        ("nonce", field(nonce)),
        ("heads", field(&joined)),
    ])
}

/// The statement a signer signs and a verifier verifies.
///
/// # Errors
///
/// As [`statement_parts`].
pub fn statement(
    request: &Request<'_>,
    person_id: &[u8; 32],
    signer: &Signatory,
    expires_at: u64,
    nonce: &[u8; NONCE_BYTES],
    heads: &[EventId],
) -> Result<Vec<u8>, ErrorClass> {
    let parts = statement_parts(request, person_id, signer, expires_at, nonce, heads)?;
    Ok(parts.into_iter().flat_map(|(_, part)| part).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(audience: &'static str) -> Request<'static> {
        Request {
            audience,
            subject: b"s",
            method: "GET",
            path: "/",
            query: "",
            body: b"",
        }
    }

    #[test]
    fn audiences() {
        for good in [
            "https://api.example.com",
            "https://a.example",
            "https://api.example.com:8443",
            "http://localhost:8787",
            "http://127.0.0.1",
            "http://[::1]",
            "http://[::1]:8080",
            "https://[2001:db8::1]",
            "https://xn--bcher-kva.example",
        ] {
            assert!(audience_ok(good), "{good}");
        }
        for bad in [
            "https://",
            "https://API.example.com",
            "https://api.example.com/",
            "https://api.example.com:443",
            "http://localhost:80",
            "http://api.example.com",
            "https://api..example.com",
            "https://api.example.com:0",
            "https://api.example.com:08443",
            "https://api.example.com:65536",
            "https://api.example.com:",
            "https://[]",
            "https://[::G]",
            "https://[::1]x",
            "https://user@api.example.com",
            "ftp://api.example.com",
            "https://api.example.com?x",
        ] {
            assert!(!audience_ok(bad), "{bad}");
        }
    }

    #[test]
    fn subjects() {
        assert!(subject_ok(b"example-subject"));
        assert!(subject_ok(" a ".as_bytes()));
        assert!(subject_ok("é".as_bytes()));
        assert!(!subject_ok(b""));
        assert!(!subject_ok(b"   "));
        assert!(!subject_ok("\u{3000}".as_bytes()));
        assert!(!subject_ok(b"a\nb"));
        assert!(!subject_ok("a\u{85}".as_bytes()));
        assert!(!subject_ok(&[0xff]));
        assert!(!subject_ok(&[b's'; 257]));
    }

    #[test]
    fn targets_split_at_the_first_question_mark() {
        assert_eq!(split_target("/a?b?c"), ("/a", "b?c"));
        assert_eq!(split_target("/a?"), ("/a", ""));
        assert_eq!(split_target("/a"), ("/a", ""));
    }

    #[test]
    fn the_longest_statement() {
        let audience = format!("https://{}.com", "a".repeat(MAX_AUDIENCE_BYTES - 12));
        let path = format!("/{}", "p".repeat(MAX_PATH_BYTES - 1));
        let query = "q".repeat(MAX_QUERY_BYTES);
        let method = "A".repeat(MAX_METHOD_BYTES);
        let longest = Request {
            audience: &audience,
            subject: &[b's'; MAX_SUBJECT_BYTES],
            method: &method,
            path: &path,
            query: &query,
            body: b"",
        };
        let heads: Vec<EventId> = (0..MAX_HEADS as u8).map(|i| EventId([i; 32])).collect();
        let signer = Signatory::from_bytes(&[0; 64]).unwrap();
        let out = statement(&longest, &[0; 32], &signer, 0, &[0; 16], &heads).unwrap();
        assert_eq!(out.len(), MAX_STATEMENT_BYTES);
        assert_eq!(MAX_STATEMENT_BYTES, 5361);
        let shortest = statement(
            &request("https://a.example"),
            &[0; 32],
            &signer,
            0,
            &[0; 16],
            &[],
        );
        assert_eq!(
            shortest.unwrap().len(),
            236 + 17 - MIN_AUDIENCE_BYTES + 3 - 1
        );
    }

    #[test]
    fn heads_are_strictly_ascending() {
        let (a, b) = (EventId([1; 32]), EventId([2; 32]));
        assert!(heads_ok(&[a, b]));
        assert!(!heads_ok(&[b, a]));
        assert!(!heads_ok(&[a, a]));
        let seventeen: Vec<EventId> = (0..17u8).map(|i| EventId([i; 32])).collect();
        assert!(!heads_ok(&seventeen));
    }

    #[test]
    fn decimals() {
        assert_eq!(decimal(b"0", 20), Some(0));
        assert_eq!(decimal(b"18446744073709551616", 20), Some(1 << 64));
        assert_eq!(decimal(b"01", 20), None);
        assert_eq!(decimal(b"", 20), None);
        assert_eq!(decimal(b"+1", 20), None);
        assert_eq!(decimal(b"111111111111111111111", 20), None);
    }
}
