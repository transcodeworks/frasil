//! Notices (keys.md, "Notices and space principals"), and keys.md's
//! "Checks against the event and its place", step 8.
//!
//! Step 8 reads only the event and the roster at its place: a key event
//! whose sealed refs name an event of the log of a space this space grants
//! carries a notice for that space (`NoticeRequired`).
//!
//! A notice's own checks never decide its event's verdict. They decide
//! whether it admits its principal at this replica, in order:
//!
//! 1. It holds T's log and `R`'s event; `R`'s visible part suffices. Else
//!    the notice is unresolved (`Pending`) until it holds them.
//! 2. `R` is valid in T's log as this replica holds it. Else `NoticeVoid`.
//! 3. `SHA-256("frasil/grant-commitment/v1" || u8(key 4) || key 3)` equals
//!    `R`'s key 3. Else `NoticeMismatch`. This checks the key and the break
//!    together.
//! 4. `R` has in its past, or is, every valid rotation of T that a valid
//!    event of this space names in its sealed refs, this event's own
//!    included. Else `NoticeStale`.
//! 5. The notice's author is a propagating member of T at `R`, a check
//!    across logs. Else `NotGranteeMember`, or unresolved (`Pending`) while
//!    the replica cannot tell.
//!
//! A notice that fails them, or is unresolved, admits nothing.

use crate::RosterClass;
use crate::across::{GranteeRotation, OtherLogs};
use crate::space::{NoticeAnswer, NoticeQuery, Notices};
use frasil_base::ErrorClass;
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_keys::KeyClass;
use frasil_keys::body::Notice;
use frasil_keys::derive::grant_commitment;

/// Checks one notice, in keys.md's order: whether it admits its principal
/// at this replica, never its event's verdict. `grantee` is what this replica
/// holds of the rotation it names, `None` when it does not hold it;
/// `stale` says that some valid rotation of the granted space that a valid
/// event of this space names in its sealed refs is not in that rotation's
/// past; `author_propagates_there` whether the notice's author is a
/// propagating member of the granted space at that rotation, `None` while
/// this replica cannot tell.
///
/// # Errors
///
/// `Pending`, `NoticeVoid`, `NoticeMismatch`, `NoticeStale`,
/// `NotGranteeMember`, or `Pending`, in that order.
pub fn check_notice(
    public: &[u8; XWING_PUBLIC],
    from_now_on: bool,
    grantee: Option<&GranteeRotation>,
    stale: bool,
    author_propagates_there: Option<bool>,
) -> Result<(), KeyClass> {
    // 1.
    let grantee = grantee.ok_or(ErrorClass::Pending)?;
    // 2.
    if !grantee.valid {
        return Err(KeyClass::NoticeVoid);
    }
    // 3.
    if grantee.grant_commitment != Some(grant_commitment(public, from_now_on)) {
        return Err(KeyClass::NoticeMismatch);
    }
    // 4.
    if stale {
        return Err(KeyClass::NoticeStale);
    }
    // 5.
    match author_propagates_there {
        None => Err(ErrorClass::Pending.into()),
        Some(false) => Err(KeyClass::NotGranteeMember),
        Some(true) => Ok(()),
    }
}

/// keys.md's step 8 and notice checks over the granted spaces among the
/// other logs a space reads: the [`Notices`] hook of a space's resolution,
/// and what a [`SpaceHistory`](super::SpaceHistory) admits.
#[derive(Debug, Clone, Copy)]
pub struct GrantedNotices<'a> {
    /// The other logs, granted spaces among them.
    pub others: &'a OtherLogs<'a>,
}

impl<'a> GrantedNotices<'a> {
    /// The notice checks over these logs.
    pub fn new(others: &'a OtherLogs<'a>) -> Self {
        Self { others }
    }

    /// Whether a notice by `author` admits its principal at this replica:
    /// it holds the granted space's log, and the notice passes every check
    /// but `NoticeStale`, which the key graph's standing rule ("in force")
    /// covers.
    pub fn admits(&self, author: &[u8; 32], notice: &Notice) -> bool {
        let Some(space) = self.others.space(&notice.space) else {
            return false;
        };
        let grantee = space.rotation(notice.rotation);
        let propagates = space.propagates_at(author, notice.rotation);
        check_notice(
            &notice.public,
            notice.from_now_on,
            grantee.as_ref(),
            false,
            propagates,
        )
        .is_ok()
    }

    /// Checks one notice of an event, at its place. A notice for a space
    /// whose log this replica does not hold stays unresolved.
    fn check_one(&self, query: &NoticeQuery<'_>, notice: &Notice) -> Result<(), RosterClass> {
        let Some(space) = self.others.space(&notice.space) else {
            return Ok(());
        };
        let grantee = space.rotation(notice.rotation);
        let stale = query.named.iter().any(|r| {
            r.log == notice.space
                && space
                    .rotation(r.id)
                    .is_some_and(|g| g.valid && g.grant_commitment.is_some())
                && r.id != notice.rotation
                && !space.precedes(r.id, notice.rotation)
        });
        let propagates = space.propagates_at(&query.author, notice.rotation);
        check_notice(
            &notice.public,
            notice.from_now_on,
            grantee.as_ref(),
            stale,
            propagates,
        )
        .map_err(RosterClass::from)
    }
}

impl Notices for GrantedNotices<'_> {
    fn check(&self, query: &NoticeQuery<'_>) -> NoticeAnswer {
        let notices = &query.opened.inner.notices;
        // Step 8, a key event's: its sealed refs that name an event of the
        // log of a space the roster at its place grants, each covered by a
        // notice for that space. A ref names the log by the space ID, so
        // this reads no other log.
        let mut answer = NoticeAnswer::default();
        if !query.opened.is_roster() {
            for r in &query.opened.inner.refs {
                if !query.granted.contains(&r.log) {
                    continue;
                }
                answer.refs_granted = true;
                if !notices.iter().any(|n| n.space == r.log) {
                    answer.covers = Some(false);
                }
            }
        }
        // Each notice's own outcome, which decides no verdict.
        answer.notices = notices
            .iter()
            .try_for_each(|notice| self.check_one(query, notice));
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::across::GrantedSpace;
    use crate::member::Level;
    use crate::screen::Opened;
    use frasil_events::{EventId, Ref};
    use frasil_keys::RotationSet;
    use frasil_keys::body::{Inner, Seal, VisiblePart};
    use frasil_keys::derive::GrantKey;
    use std::collections::{BTreeMap, BTreeSet};
    use zeroize::Zeroizing;

    const T: EventId = EventId([0x70; 32]);
    const T1: EventId = EventId([0x71; 32]);
    const T2: EventId = EventId([0x72; 32]);
    const AUTHOR: [u8; 32] = [0xaa; 32];

    /// A granted space T with rotations T1 and T2 (T1 before T2), whose
    /// grant keys derive from fixed seeds; the author propagates at both.
    struct Team {
        others: OtherLogs<'static>,
        void: BTreeSet<EventId>,
        keys: frasil_crypto::device::KeyRing,
    }

    fn key(rotation: EventId) -> GrantKey {
        GrantKey::derive(&rotation.0)
    }

    impl GrantedSpace for Team {
        fn space_id(&self) -> EventId {
            T
        }
        fn holds(&self, event: EventId) -> bool {
            event == T1 || event == T2
        }
        fn precedes(&self, earlier: EventId, later: EventId) -> bool {
            earlier == T1 && later == T2
        }
        fn other_logs(&self) -> &OtherLogs<'_> {
            &self.others
        }
        fn keys(&self) -> &frasil_crypto::device::KeyRing {
            &self.keys
        }
        fn names(&self, _device: &frasil_crypto::device::DeviceId) -> bool {
            false
        }
        fn effective(
            &self,
            _depth: usize,
            _seen: &[EventId],
        ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
            BTreeMap::from([(AUTHOR, (Level::Write, Some(Level::Write)))])
        }
        fn reach(
            &self,
            _device: &[u8; 32],
            _paths: crate::PathsFor,
        ) -> Option<crate::graph::Reach> {
            None
        }
        fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
            BTreeSet::from([AUTHOR])
        }
        fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
            BTreeSet::from([AUTHOR])
        }
        fn ends(&self, _device: &[u8; 32]) -> Vec<Ref> {
            Vec::new()
        }
        fn rotation(&self, id: EventId) -> Option<GranteeRotation> {
            self.holds(id).then(|| GranteeRotation {
                valid: !self.void.contains(&id),
                grant_commitment: Some(key(id).commitment(false)),
            })
        }
        fn propagates_at(&self, device: &[u8; 32], _rotation: EventId) -> Option<bool> {
            Some(*device == AUTHOR)
        }
    }

    fn opened(refs: Vec<Ref>, notices: Vec<Notice>) -> Opened {
        Opened {
            visible: VisiblePart {
                seal: Seal::Under(RotationSet::single(EventId([1; 32]))),
                deliveries: Vec::new(),
                sealed: vec![0; 41],
                nonce: None,
                commitment: [0; 32],
                twin: None,
            },
            inner: Inner {
                refs,
                notices,
                ..Inner::default()
            },
            body_key: Zeroizing::new([0; 32]),
            provisional: false,
            part: None,
        }
    }

    fn notice(rotation: EventId, public_of: EventId) -> Notice {
        Notice {
            space: T,
            rotation,
            public: key(public_of).public,
            from_now_on: false,
        }
    }

    fn answer(
        team: Option<&Team>,
        opened: &Opened,
        author: [u8; 32],
        named: &[Ref],
    ) -> NoticeAnswer {
        let mut others = OtherLogs::none();
        if let Some(team) = team {
            others = others.with_space(team);
        }
        let query = NoticeQuery {
            event: EventId([9; 32]),
            author,
            opened,
            granted: BTreeSet::from([T]),
            named: named.iter().copied().collect(),
        };
        GrantedNotices::new(&others).check(&query)
    }

    fn team() -> Team {
        Team {
            keys: frasil_crypto::device::KeyRing::new(),
            others: OtherLogs::none(),
            void: BTreeSet::new(),
        }
    }

    const REF_T1: Ref = Ref { log: T, id: T1 };
    const REF_T2: Ref = Ref { log: T, id: T2 };

    #[test]
    fn a_response_with_its_notice_passes() {
        let team = team();
        let body = opened(vec![REF_T1], vec![notice(T1, T1)]);
        let got = answer(Some(&team), &body, AUTHOR, &[REF_T1]);
        assert!(got.refs_granted);
        assert_eq!(got.covers, Some(true));
        assert_eq!(got.notices, Ok(()));
        // A later grant rotation that has it in its past covers it too.
        let body = opened(vec![REF_T1], vec![notice(T2, T2)]);
        let got = answer(Some(&team), &body, AUTHOR, &[REF_T1]);
        assert_eq!((got.covers, got.notices), (Some(true), Ok(())));
    }

    #[test]
    fn a_response_without_a_notice_needs_one() {
        let team = team();
        let body = opened(vec![REF_T2], vec![]);
        let got = answer(Some(&team), &body, AUTHOR, &[REF_T2]);
        assert_eq!((got.refs_granted, got.covers), (true, Some(false)));
        // Without the granted space's log the replica decides the same.
        let got = answer(None, &body, AUTHOR, &[REF_T2]);
        assert_eq!((got.refs_granted, got.covers), (true, Some(false)));
        // Any notice for the space covers the refs, whatever it names; its
        // own checks decide only what it admits.
        let body = opened(vec![REF_T2], vec![notice(T1, T2)]);
        for team in [Some(&team), None] {
            let got = answer(team, &body, AUTHOR, &[REF_T2]);
            assert_eq!((got.refs_granted, got.covers), (true, Some(true)));
        }
    }

    #[test]
    fn a_notice_admits_only_where_it_checks() {
        let team = team();
        let mut others = OtherLogs::none();
        others = others.with_space(&team);
        let with_log = GrantedNotices::new(&others);
        let none = OtherLogs::none();
        let without_log = GrantedNotices::new(&none);
        assert!(with_log.admits(&AUTHOR, &notice(T1, T1)));
        assert!(!without_log.admits(&AUTHOR, &notice(T1, T1)));
        assert!(!with_log.admits(&AUTHOR, &notice(T1, T2)));
        assert!(!with_log.admits(&[0xbb; 32], &notice(T1, T1)));
    }

    #[test]
    fn each_notice_is_checked_in_order() {
        let mut team = team();
        let class = |got: NoticeAnswer| got.notices.err().map(frasil_base::errors::Class::name);
        // A key the rotation did not commit to.
        let body = opened(vec![], vec![notice(T1, T2)]);
        assert_eq!(
            class(answer(Some(&team), &body, AUTHOR, &[])),
            Some("NoticeMismatch")
        );
        // A principal out of force: a valid event named T2.
        let body = opened(vec![], vec![notice(T1, T1)]);
        assert_eq!(
            class(answer(Some(&team), &body, AUTHOR, &[REF_T2])),
            Some("NoticeStale")
        );
        // An author that is no member of T.
        assert_eq!(
            class(answer(Some(&team), &body, [0xbb; 32], &[])),
            Some("NotGranteeMember")
        );
        // No log of T: the notice stays unresolved, and the event stands.
        assert_eq!(answer(None, &body, AUTHOR, &[]).notices, Ok(()));
        // A void rotation.
        team.void.insert(T1);
        assert_eq!(
            class(answer(Some(&team), &body, AUTHOR, &[])),
            Some("NoticeVoid")
        );
    }
}
