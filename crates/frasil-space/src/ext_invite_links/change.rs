//! The invite grant and the successor (ext-invite-links.md, "The invite
//! grant and the successor").
//!
//! An **invite grant** is an op-0 change whose member is `[3, K]`:
//!
//! | Key | Field | Rule |
//! |---|---|---|
//! | 2 | `level` | required: `read` or `write`; `administer` is `AdministerNotDevice` |
//! | 3, 4 | `capabilities`, `label` | optional, as roster.md |
//! | 5, 6 | `history`, `via` | required; `via` is 1 |
//! | 7 | `session` | optional: a guest invite, whose `claims` is 0 |
//! | 9, 10, 12 | keys and proof | required: `K`'s X-Wing and ML-DSA-65 keys, and its proof over them |
//! | 13 | `expires_at` | required |
//! | 14 | `claims` | required: 0, a device claims it; 1, a person does |
//!
//! `[3, K]` appears only in a grant, in a removal and as a successor's
//! author; a change (op 1) of it is `Malformed`. A **successor**'s one
//! change is `{0: 4, 1: claimant}`, the claimant `[1, person ID]` or
//! `[0, device ID]`, with keys 9, 10 and 12 exactly for a device.
//!
//! [`read_change`] reads a change that uses one of the reserved hooks, in
//! order:
//!
//! ```text
//! 1. Op 4: a claimant of type 0 or 1 with a 32-byte ID; a person's
//!    change has keys 0 and 1 only, a device's keys 0, 1, 9, 10 and
//!    12 only, whose keys and proof pass as a device grant's.        else Malformed / that class
//! 2. Member type 3: a 32-byte ID. A removal has keys 0 and 1 only;
//!    any op but a grant or a removal is Malformed. A grant: the
//!    keys of its row; via 1; expires_at an unsigned integer; claims
//!    0 or 1; session only with claims 0.                            else Malformed
//!    Not administer.                                                else AdministerNotDevice
//!    Its keys and proof as a device grant's.                        else that class
//! 3. Any other change with key 14.                                  else Malformed
//! ```

use crate::DeviceKeys;
use crate::change::{Change, Op, key};
use crate::member::{HistoryMode, Level, MemberRef, MemberType, Via};
use crate::{Limits, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::DeviceId;
use std::sync::Arc;

/// `claims` 0: a device claims the invite.
pub const CLAIMS_DEVICE: u64 = 0;
/// `claims` 1: a person claims the invite.
pub const CLAIMS_PERSON: u64 = 1;

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// The member `[3, K]` of an invite key.
pub fn invite_member(key: [u8; 32]) -> MemberRef {
    MemberRef {
        kind: MemberType::Invite,
        id: key,
    }
}

/// An invite grant of `K`, whose keys are `keys`, at `level`
/// (`read` or `write`), with `expires_at` and `claims`.
pub fn invite_grant(
    key: [u8; 32],
    keys: DeviceKeys,
    level: Level,
    history: HistoryMode,
    expires_at: u64,
    claims: u64,
) -> Change {
    Change {
        level: Some(level),
        history: Some(history),
        via: Some(Via::Link),
        keys: Some(Arc::new(keys)),
        expires_at: Some(expires_at),
        claims: Some(claims),
        ..Change::new(Op::Grant, Some(invite_member(key)))
    }
}

/// A successor's one change, granting `claimant`: a person, or a device
/// with its keys.
pub fn successor(claimant: MemberRef, keys: Option<DeviceKeys>) -> Change {
    Change {
        keys: keys.map(Arc::new),
        ..Change::new(Op::Succeed, Some(claimant))
    }
}

/// The removal of an invite key: a revocation, or after a valid successor
/// the close.
pub fn revoke_invite(key: [u8; 32]) -> Change {
    Change::remove(invite_member(key))
}

/// The member a change names, as `(type code, ID)`, if it is an array of an
/// unsigned type and 32 bytes.
fn member_of(map: &Map) -> Result<(u64, [u8; 32]), SpaceClass> {
    let items = map.get(&key::MEMBER).ok_or_else(malformed)?.as_array()?;
    let [kind, id] = items else {
        return Err(malformed());
    };
    Ok((kind.as_unsigned()?, id.as_byte_array::<32>()?))
}

/// Whether a map's keys are exactly these.
fn keys_are(map: &Map, keys: &[u64]) -> bool {
    map.len() == keys.len() && keys.iter().all(|k| map.contains_key(k))
}

/// Reads a change that uses one of ext-invite-links.md's reserved hooks:
/// op 4, member type 3 or key 14. `Change::read` has read the map and its
/// op, which is below 5.
pub(crate) fn read_change(
    value: &Value,
    space: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<Change, SpaceClass> {
    let map = value.as_map()?;
    let op = map.get(&key::OP).ok_or_else(malformed)?.as_unsigned()?;
    let op = Op::from_code(op).ok_or_else(malformed)?;
    // 1.
    if op == Op::Succeed {
        return read_successor(map, space, limits);
    }
    // 2.
    let member = map.get(&key::MEMBER).and_then(MemberRef::peek_type);
    if member == Some(MemberType::Invite.code()) {
        return read_invite(map, op, space, limits);
    }
    // 3.
    Err(malformed())
}

/// Step 1: a successor.
fn read_successor(
    map: &Map,
    space: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<Change, SpaceClass> {
    let (kind, id) = member_of(map)?;
    match MemberType::from_code(kind) {
        Some(MemberType::Person) if keys_are(map, &[key::OP, key::MEMBER]) => {
            Ok(successor(MemberRef::person(id), None))
        }
        Some(MemberType::Device)
            if keys_are(
                map,
                &[
                    key::OP,
                    key::MEMBER,
                    key::EXCHANGE_HYBRID,
                    key::MLDSA,
                    key::ED25519,
                ],
            ) =>
        {
            // Its keys, as a device grant's.
            let mut probe = map.clone();
            probe.insert(key::OP, Value::Unsigned(Op::Grant.code()));
            probe.insert(key::LEVEL, Value::Unsigned(Level::Read.code()));
            probe.insert(key::HISTORY, Value::Unsigned(HistoryMode::FromNowOn.code()));
            probe.insert(key::VIA, Value::Unsigned(Via::Link.code()));
            let grant = Change::read(&Value::Map(probe), space, limits)?;
            Ok(Change {
                keys: grant.keys,
                ..Change::new(Op::Succeed, grant.member)
            })
        }
        _ => Err(malformed()),
    }
}

/// Step 2: a grant or removal of an invite key.
fn read_invite(
    map: &Map,
    op: Op,
    space: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<Change, SpaceClass> {
    let (_, id) = member_of(map)?;
    let member = invite_member(id);
    match op {
        Op::Remove if keys_are(map, &[key::OP, key::MEMBER]) => return Ok(Change::remove(member)),
        Op::Grant => {}
        _ => return Err(malformed()),
    }
    const ALLOWED: [u64; 13] = [
        key::OP,
        key::MEMBER,
        key::LEVEL,
        key::CAPABILITIES,
        key::LABEL,
        key::HISTORY,
        key::VIA,
        key::SESSION,
        key::EXCHANGE_HYBRID,
        key::MLDSA,
        key::ED25519,
        key::EXPIRES_AT,
        key::CLAIMS,
    ];
    const REQUIRED: [u64; 8] = [
        key::LEVEL,
        key::HISTORY,
        key::VIA,
        key::EXCHANGE_HYBRID,
        key::MLDSA,
        key::ED25519,
        key::EXPIRES_AT,
        key::CLAIMS,
    ];
    if !map.keys().all(|k| ALLOWED.contains(k)) || !REQUIRED.iter().all(|k| map.contains_key(k)) {
        return Err(malformed());
    }
    let via = map[&key::VIA].as_unsigned().ok();
    let expires_at = map[&key::EXPIRES_AT].as_unsigned().ok();
    let claims = map[&key::CLAIMS].as_unsigned().ok();
    let (Some(Via::Link), Some(expires_at), Some(claims @ (CLAIMS_DEVICE | CLAIMS_PERSON))) =
        (via.and_then(Via::from_code), expires_at, claims)
    else {
        return Err(malformed());
    };
    if map.contains_key(&key::SESSION) && claims != CLAIMS_DEVICE {
        return Err(malformed());
    }
    if map[&key::LEVEL].as_unsigned().ok() == Some(Level::Administer.code()) {
        return Err(SpaceClass::AdministerNotDevice);
    }
    // Its keys and proof, and its other fields, as a device grant's.
    let mut probe = map.clone();
    probe.remove(&key::EXPIRES_AT);
    probe.remove(&key::CLAIMS);
    probe.insert(key::MEMBER, MemberRef::device(DeviceId(id)).to_value());
    let grant = Change::read(&Value::Map(probe), space, limits)?;
    Ok(Change {
        member: Some(member),
        expires_at: Some(expires_at),
        claims: Some(claims),
        ..grant
    })
}

/// "The invite grant and the successor": a successor does not rotate, and
/// its change is its event's only one; else `Malformed`.
///
/// # Errors
///
/// `Malformed`.
pub fn check_successor_part(changes: &[Change], rotates: bool) -> Result<(), SpaceClass> {
    if changes.iter().any(|c| c.op == Op::Succeed) && (changes.len() != 1 || rotates) {
        return Err(malformed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::Class;

    fn read(value: Value) -> Result<Change, &'static str> {
        Change::read(&value, Some(&[9; 32]), &Limits::PROTOCOL).map_err(Class::name)
    }

    fn map(pairs: &[(u64, Value)]) -> Value {
        Value::Map(pairs.iter().cloned().collect())
    }

    fn member(kind: u64, id: [u8; 32]) -> Value {
        Value::Array(vec![Value::Unsigned(kind), Value::Bytes(id.to_vec())])
    }

    #[test]
    fn successors_and_removals_read() {
        let person = map(&[(0, Value::Unsigned(4)), (1, member(1, [1; 32]))]);
        let read_back = read(person.clone()).unwrap();
        assert_eq!(read_back.op, Op::Succeed);
        assert_eq!(read_back.to_value(), person);
        let removal = map(&[(0, Value::Unsigned(2)), (1, member(3, [1; 32]))]);
        assert_eq!(read(removal.clone()).unwrap().to_value(), removal);
        let change = map(&[
            (0, Value::Unsigned(1)),
            (1, member(3, [1; 32])),
            (2, Value::Unsigned(0)),
        ]);
        assert_eq!(read(change), Err("Malformed"));
        let space = map(&[(0, Value::Unsigned(4)), (1, member(2, [1; 32]))]);
        assert_eq!(read(space), Err("Malformed"));
        let claims = map(&[
            (0, Value::Unsigned(2)),
            (1, member(1, [1; 32])),
            (14, Value::Unsigned(1)),
        ]);
        assert_eq!(read(claims), Err("Malformed"));
        let device = map(&[(0, Value::Unsigned(4)), (1, member(0, [1; 32]))]);
        assert_eq!(read(device), Err("Malformed"));
    }

    #[test]
    fn a_successor_is_alone_and_does_not_rotate() {
        let one = [successor(MemberRef::person([1; 32]), None)];
        assert_eq!(check_successor_part(&one, false), Ok(()));
        assert_eq!(
            check_successor_part(&one, true).map_err(Class::name),
            Err("Malformed")
        );
        let two = [
            successor(MemberRef::person([1; 32]), None),
            revoke_invite([2; 32]),
        ];
        assert_eq!(
            check_successor_part(&two, false).map_err(Class::name),
            Err("Malformed")
        );
        assert_eq!(check_successor_part(&two[1..], true), Ok(()));
    }
}
