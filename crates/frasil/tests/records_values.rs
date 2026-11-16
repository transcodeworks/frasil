//! Records cells of every type the records subset holds (adapter-records.md,
//! section 2.1), written and read back through the client.
#![cfg(feature = "adapter-records")]

use frasil::{Device, Error, Storage, Value};

#[tokio::test]
async fn cells_keep_integers_floats_and_booleans() {
    let device = Device::open(Storage::Memory, &[3; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let table = space.create_records().unwrap();
    table
        .write(|tx| {
            tx.insert("t", b"r")
                .set("t", b"r", "count", 7u64)
                .set("t", b"r", "delta", -42i64)
                .set("t", b"r", "min", i64::MIN)
                .set("t", b"r", "ratio", 0.25f64)
                .set("t", b"r", "zero", -0.0f64)
                .set("t", b"r", "done", true)
                .set(
                    "t",
                    b"r",
                    "mixed",
                    Value::Array(vec![Value::from(1.5), Value::from(-1i64), false.into()]),
                );
        })
        .await
        .unwrap();
    let row = table.row("t", b"r").await.unwrap().unwrap();
    assert_eq!(row["count"], Value::Unsigned(7));
    assert_eq!(row["delta"].as_i64(), Ok(-42));
    assert_eq!(row["min"].as_i64(), Ok(i64::MIN));
    assert_eq!(row["ratio"].as_f64(), Ok(0.25));
    assert!(row["zero"].as_f64().unwrap().is_sign_negative());
    assert_ne!(row["zero"], Value::Float(0.0));
    assert_eq!(row["done"].as_bool(), Ok(true));
    assert_eq!(
        row["mixed"],
        Value::Array(vec![
            Value::Float(1.5),
            Value::Negative(0),
            Value::Bool(false)
        ])
    );
    // An integer and a float are two values.
    assert_ne!(Value::from(1u64), Value::from(1.0));

    // A NaN has no encoding: the write is refused, and nothing changes.
    let refused = table
        .write(|tx| {
            tx.set("t", b"r", "ratio", f64::NAN);
        })
        .await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(!matches!(refused, Err(Error::UnknownSpace)));
    let row = table.row("t", b"r").await.unwrap().unwrap();
    assert_eq!(row["ratio"].as_f64(), Ok(0.25));
    device.close().await.unwrap();
}
