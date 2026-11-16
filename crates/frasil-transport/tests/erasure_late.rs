//! The late-erasure wire answer, including exact-key and standing checks.
use frasil_base::cbor::{self, Value};
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::messages::ErasureLate;

fn read(bytes: &[u8]) -> Result<ErasureLate, frasil_transport::TransportClass> {
    ErasureLate::read(
        &read_message(
            bytes,
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            Extensions::NONE,
        )?
        .unwrap(),
    )
}

#[test]
fn standing_and_exact_keys() {
    let mut answer = ErasureLate {
        space: [1; 32],
        erasure: [2; 32],
        cut: vec![3],
        checkpoint: [4; 32],
        standing: 0,
    };
    for standing in 0..=2 {
        answer.standing = standing;
        assert_eq!(read(&answer.encode()).unwrap(), answer);
    }
    for connection in [ConnectionKind::Member, ConnectionKind::Nearby] {
        assert!(
            read_message(
                &answer.encode(),
                StreamClass::Control,
                connection,
                Extensions::NONE
            )
            .is_err()
        );
    }
    answer.standing = 3;
    assert!(read(&answer.encode()).is_err());
    answer.standing = 0;
    let Value::Map(mut map) = cbor::decode(&answer.encode()).unwrap() else {
        panic!("map")
    };
    map.insert(6, 0u64.into());
    assert!(read(&Value::Map(map.clone()).encode()).is_err());
    map.remove(&6);
    map.insert(4, Value::Bytes(vec![4; 31]));
    assert!(read(&Value::Map(map.clone()).encode()).is_err());
    map.remove(&4);
    assert!(read(&Value::Map(map).encode()).is_err());
}

#[test]
fn largest_storage_cut_fits_the_late_answer() {
    let answer = ErasureLate {
        space: [1; 32],
        erasure: [2; 32],
        cut: vec![0; 262_144],
        checkpoint: [3; 32],
        standing: 0,
    };
    assert!(answer.encode().len() <= 266_240);
    assert_eq!(read(&answer.encode()).unwrap(), answer);
}
