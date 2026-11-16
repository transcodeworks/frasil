//! The ErasureLate message reader on arbitrary bytes.
#![no_main]
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::messages::ErasureLate;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(Some(message)) = read_message(
        data,
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        Extensions::NONE,
    ) && let Ok(answer) = ErasureLate::read(&message)
    {
        assert_eq!(answer.encode(), data);
        assert!(answer.standing <= 2);
    }
});
