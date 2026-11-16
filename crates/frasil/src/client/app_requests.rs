//! Signed application requests (ext-app-requests.md): a device signs an
//! HTTP request to an application's server, beside the account's access
//! token, and the server verifies that a device of the account's person
//! sent it.

use super::{Device, MemberId, PersonId};
use crate::error::{Error, Result};
use frasil_app_requests::{HeldList, ReceivedHeaders, Request, Verifier, VerifierState};

pub use frasil_app_requests::NonceStore;

/// The headers of a signed request, by name, to send with it unchanged.
pub type SignedHeaders = Vec<(String, String)>;

/// The audience, path and query of an absolute URL: the audience its
/// origin in canonical form, the scheme and host in lower case and no
/// default port; the path `/` when it has none. A fragment is dropped.
fn split_url(url: &str) -> Result<(String, &str, &str)> {
    let url = url.split('#').next().unwrap_or(url);
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(Error::Invalid("a request URL is absolute"))?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => return Err(Error::Invalid("a request URL is http or https")),
    };
    let at = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(at);
    let mut host = authority.to_ascii_lowercase();
    if let Some(bare) = host.strip_suffix(default) {
        host = bare.to_owned();
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = if path.is_empty() { "/" } else { path };
    Ok((format!("{scheme}://{host}"), path, query))
}

/// A verifier's configured audience in canonical form: an http or https
/// origin, with at most a `/` after it.
fn configured_audience(origin: &str) -> Result<String> {
    const NOT_AN_ORIGIN: Error = Error::Invalid("a verifier's audience is an http or https origin");
    let (audience, path, query) = split_url(origin).map_err(|_| NOT_AN_ORIGIN)?;
    if path != "/" || !query.is_empty() || origin.contains('#') {
        return Err(NOT_AN_ORIGIN);
    }
    if !frasil_app_requests::statement::audience_ok(&audience) {
        return Err(NOT_AN_ORIGIN);
    }
    Ok(audience)
}

/// The path and query of a request target: its origin form (`/v1/x?y=1`)
/// or an absolute URL, whose origin is not read. A fragment is dropped.
fn split_target(target: &str) -> Result<(&str, &str)> {
    if target.starts_with('/') {
        let target = target.split('#').next().unwrap_or(target);
        return Ok(target.split_once('?').unwrap_or((target, "")));
    }
    let (_, path, query) = split_url(target)?;
    Ok((path, query))
}

impl Device {
    /// The list delivery of this device's person (ext-app-requests.md,
    /// "The list delivery"): every event of its merged list, each after
    /// its parents, as the deterministic CBOR body of a signed
    /// `PUT /frasil/p1/device-list` at the verifier's origin, with
    /// `Content-Type: application/cbor`. Send it after a verifier refuses
    /// `device_list_needed`, then retry the request once, signed again; or
    /// after `X-Frasil-List-Needed: 1`.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person, or one that holds
    /// no list of its person.
    pub async fn list_delivery(&self) -> Result<Vec<u8>> {
        let engine = self.engine();
        let person = engine
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let events = engine.list_events(&person).await;
        if events.is_empty() {
            return Err(Error::NotAllowed("the device holds no list of its person"));
        }
        Ok(frasil_app_requests::delivery::encode_delivery(&events))
    }

    /// Signs a request to an application's server: the headers to send
    /// with it, beside its access token. `subject` is the token's subject
    /// (`sub`), `url` the absolute URL the request goes to, and `body` the
    /// exact bytes it sends. The headers live 60 seconds. The HTTP client
    /// must follow no redirect.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person, or without a known
    /// wall clock; [`Error::Invalid`] for a URL that is not absolute http
    /// or https; `Malformed` for a subject, method, path or query outside
    /// its shape.
    pub async fn sign_request(
        &self,
        subject: &str,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> Result<SignedHeaders> {
        let engine = self.engine();
        let person = engine
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let heads = engine
            .lock()
            .await
            .lists
            .get(&person)
            .map(|list| match list.whole() {
                Some(list) => frasil_app_requests::heads_to_send(list),
                None => {
                    let mut heads = list.heads();
                    heads.sort_unstable();
                    heads
                }
            })
            .unwrap_or_default();
        let (audience, path, query) = split_url(url)?;
        let signed_at = engine.platform().clock.wall().ok_or(Error::NotAllowed(
            "signing a request needs a known wall clock",
        ))?;
        let nonce = engine.platform().nonce::<16>()?;
        let request = Request {
            audience: &audience,
            subject: subject.as_bytes(),
            method,
            path,
            query,
            body,
        };
        let signed = frasil_app_requests::sign(
            &engine.keys().identity_seed_bytes(),
            engine.signer().kc(),
            &request,
            &person,
            signed_at,
            nonce,
            &heads,
        )
        .map_err(Error::class)?;
        Ok(signed
            .values()
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect())
    }
}

/// What a verifier keeps durably: per subject, the person recorded at its
/// first accepted request; per person, the list events placed, each with
/// the verifier's first sight of it, in seconds. A server keeps them in
/// its own storage; the lists only grow.
pub trait DeviceLists {
    /// The person recorded for a subject, if any.
    fn recorded_person(&self, subject: &str) -> Option<PersonId>;

    /// Records a subject's person.
    fn record_person(&mut self, subject: &str, person: PersonId);

    /// A person's placed list events with their first sights; empty when
    /// none is held.
    fn list(&self, person: &PersonId) -> Vec<(Vec<u8>, u64)>;

    /// Keeps a person's placed list events, the whole list.
    fn keep_list(&mut self, person: &PersonId, events: Vec<(Vec<u8>, u64)>);
}

/// A request the verifier accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedRequest {
    /// The person whose device signed it.
    pub person: PersonId,
    /// The device that signed it.
    pub device: MemberId,
    /// The request names list events the verifier lacks: answer with
    /// `X-Frasil-List-Needed: 1`, and the device delivers its list.
    pub list_needed: bool,
}

/// The verifier of signed requests, at an application's server. It does
/// no IO: its state comes through [`DeviceLists`] and [`NonceStore`].
///
/// Its audience, the server's own origin, is fixed when it is made and
/// never read from a request: a server that took it from `Host` would
/// accept a request signed for another server and sent to it with that
/// server's name (ext-app-requests.md, 3.2 Verifying).
#[derive(Debug)]
pub struct RequestVerifier<L, N> {
    audience: String,
    lists: L,
    nonces: N,
    clock: fn() -> Option<u64>,
}

#[cfg(not(target_arch = "wasm32"))]
fn system_wall() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

#[cfg(target_arch = "wasm32")]
fn system_wall() -> Option<u64> {
    None
}

impl<L: DeviceLists, N: NonceStore> RequestVerifier<L, N> {
    /// A verifier for the server at `audience`, its origin such as
    /// `https://api.example.org`, taken from the server's configuration,
    /// over this state, with the system's wall clock; in WebAssembly,
    /// supply one with [`RequestVerifier::with_clock`]. It refuses a
    /// request signed for any other origin.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an audience that is not an http or https
    /// origin, or whose canonical form is outside ext-app-requests.md's
    /// shape (2.2): `http` only on a loopback host.
    pub fn new(audience: &str, lists: L, nonces: N) -> Result<Self> {
        Ok(Self {
            audience: configured_audience(audience)?,
            lists,
            nonces,
            clock: system_wall,
        })
    }

    /// The audience, in canonical form.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Another wall clock, in seconds since the epoch, `None` when unknown.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> Option<u64>) -> Self {
        self.clock = clock;
        self
    }

    /// The state, to persist or inspect.
    pub fn into_parts(self) -> (L, N) {
        (self.lists, self.nonces)
    }

    /// Verifies a request as the server received it: `subject` the
    /// verified access token's subject (`sub`), `target` its path and
    /// query (`/v1/x?y=1`) or its absolute URL, `headers` all its headers,
    /// `body` its exact bytes. The statement names the verifier's own
    /// audience: the origin of an absolute `target` is not read, so a
    /// request signed for another origin fails its signature. A list
    /// delivery (`PUT /frasil/p1/device-list`) is placed on the way.
    ///
    /// # Errors
    ///
    /// The refusal's class, such as `Unsigned`, `BadSignature`, `Expired`,
    /// `Replayed`, `WrongPerson`, `ListNeeded` or `NotASigner`, whose
    /// answer `frasil-app-requests`' codes give; [`Error::Invalid`] for a
    /// target that is neither a path nor an absolute http or https URL.
    pub fn verify<H: AsRef<str>, V: AsRef<str>>(
        &mut self,
        subject: &str,
        method: &str,
        target: &str,
        headers: &[(H, V)],
        body: &[u8],
    ) -> Result<VerifiedRequest> {
        let audience = self.audience.as_str();
        let (path, query) = split_target(target)?;
        let received = ReceivedHeaders::from_pairs(
            headers
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_ref().as_bytes())),
        );
        let request = Request {
            audience,
            subject: subject.as_bytes(),
            method,
            path,
            query,
            body,
        };
        let person = frasil_app_requests::SignedHeaders::read(&received)
            .ok()
            .map(|signed| signed.person_id);
        let mut state = Loaded::load(&self.lists, subject, person);
        let verified = Verifier::default().verify(
            &received,
            &request,
            &mut state,
            Some(&mut self.nonces as &mut dyn NonceStore),
            (self.clock)(),
        );
        state.store(&mut self.lists, subject);
        let verified = verified.map_err(|refusal| Error::Class(refusal.name()))?;
        Ok(VerifiedRequest {
            person: MemberId::from_bytes(verified.person_id),
            device: MemberId::device(verified.device),
            list_needed: verified.list_needed,
        })
    }
}

/// The records of one subject and one person, loaded for a request and
/// written back after it.
struct Loaded {
    recorded: Option<[u8; 32]>,
    record: Option<[u8; 32]>,
    list: Option<HeldList>,
    changed: bool,
}

impl Loaded {
    fn load(lists: &impl DeviceLists, subject: &str, person: Option<[u8; 32]>) -> Self {
        let list = person.and_then(|person| {
            let events = lists.list(&MemberId::from_bytes(person));
            if events.is_empty() {
                return None;
            }
            HeldList::restore(events.iter().map(|(event, seen)| (event.as_slice(), *seen))).ok()
        });
        Self {
            recorded: lists
                .recorded_person(subject)
                .map(|person| *person.as_bytes()),
            record: None,
            list,
            changed: false,
        }
    }

    fn store(self, lists: &mut impl DeviceLists, subject: &str) {
        if let Some(person) = self.record {
            lists.record_person(subject, MemberId::from_bytes(person));
        }
        if let (true, Some(list)) = (self.changed, self.list) {
            lists.keep_list(&MemberId::from_bytes(list.person_id()), list.events());
        }
    }
}

impl VerifierState for Loaded {
    fn recorded_person(&self, _subject: &[u8]) -> Option<[u8; 32]> {
        self.recorded
    }

    fn record_person(&mut self, _subject: &[u8], person_id: [u8; 32]) {
        self.record = Some(person_id);
    }

    fn list(&self, person_id: &[u8; 32]) -> Option<&HeldList> {
        self.list
            .as_ref()
            .filter(|list| list.person_id() == *person_id)
    }

    fn list_mut(&mut self, person_id: &[u8; 32]) -> Option<&mut HeldList> {
        self.changed = true;
        self.list
            .as_mut()
            .filter(|list| list.person_id() == *person_id)
    }

    fn insert_list(&mut self, list: HeldList) {
        self.changed = true;
        self.list = Some(list);
    }
}

#[cfg(test)]
mod tests {
    use super::{configured_audience, split_target, split_url};

    #[test]
    fn a_url_splits_into_its_audience_path_and_query() {
        let (audience, path, query) = split_url("HTTPS://Api.Example.org:443/v1/x?y=1#f").unwrap();
        assert_eq!(
            (audience.as_str(), path, query),
            ("https://api.example.org", "/v1/x", "y=1")
        );
        let (audience, path, query) = split_url("http://localhost:8080").unwrap();
        assert_eq!(
            (audience.as_str(), path, query),
            ("http://localhost:8080", "/", "")
        );
        assert!(split_url("example.org/x").is_err());
    }

    #[test]
    fn a_configured_audience_is_an_origin_in_canonical_form() {
        assert_eq!(
            configured_audience("HTTPS://Api.Example.org:443/").unwrap(),
            "https://api.example.org"
        );
        assert_eq!(
            configured_audience("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        for bad in [
            "https://api.example.org/v1",
            "https://api.example.org/?x=1",
            "https://api.example.org#f",
            "http://api.example.org",
            "api.example.org",
            "ftp://api.example.org",
        ] {
            assert!(configured_audience(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_target_gives_its_path_and_query_and_no_origin() {
        assert_eq!(split_target("/v1/x?y=1#f").unwrap(), ("/v1/x", "y=1"));
        assert_eq!(
            split_target("https://other.example/v1/x?y=1").unwrap(),
            ("/v1/x", "y=1")
        );
        assert!(split_target("v1/x").is_err());
    }
}
