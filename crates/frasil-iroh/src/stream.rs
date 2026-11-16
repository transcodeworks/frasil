//! Frames on QUIC streams (transport.md, sections 2.3 "Frames and stream
//! classes", 3.1 "Reading a frame" and 3.16's stream table).
//!
//! ```text
//! frame = u32be(len(message)) || message
//! ```
//!
//! A [`FrameReceiver`] reads one stream frame by frame. It checks each
//! 4-byte prefix against the stream class's cap before it allocates the
//! payload, then runs `read_frame`'s other steps through
//! `frasil_transport::frame::read_message`. A failure closes the connection
//! with section 2.5's code, as section 3.1 says.

use crate::Error;
use frasil_transport::frame::{ConnectionKind, Extensions, Message, StreamClass, read_message};
use iroh::endpoint::{ReadExactError, RecvStream, SendStream, VarInt};

/// The most a frame's buffer holds before any of its bytes arrive; past
/// it, the buffer grows to at most twice the bytes that arrived.
const FIRST_READ: usize = 64 * 1024;

/// A stream class's priority (section 3.16): a higher one is sent first.
pub const fn priority(class: StreamClass) -> i32 {
    match class {
        StreamClass::Ephemeral => 3,
        StreamClass::Control | StreamClass::Nearby => 2,
        StreamClass::Sync => 1,
        StreamClass::Object => 0,
    }
}

/// The sending half of a stream of one class.
#[derive(Debug)]
pub struct FrameSender {
    stream: SendStream,
    class: StreamClass,
}

impl FrameSender {
    pub(crate) fn new(stream: SendStream, class: StreamClass) -> Self {
        // The stream may already be closed; its first write will say so.
        let _ = stream.set_priority(priority(class));
        Self { stream, class }
    }

    /// The stream's class.
    pub fn class(&self) -> StreamClass {
        self.class
    }

    /// Sends one message as a frame, `u32be(len(message)) || message`.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a message over the class's cap, which is not sent;
    /// `Io` if the stream or the connection failed.
    pub async fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        if message.len() > self.class.cap() {
            return Err(Error::protocol(frasil_crypto::ErrorClass::TooLarge));
        }
        self.write_bytes(&frasil_transport::frame::frame(message))
            .await
    }

    /// Writes bytes on the stream as they are, framed or not. A relay that
    /// passes frames between two connections uses it, and so do tests of
    /// what a receiver refuses.
    ///
    /// # Errors
    ///
    /// `Io` if the stream or the connection failed.
    pub async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stream
            .write_all(bytes)
            .await
            .map_err(|error| write_error(&error))
    }

    /// Ends the stream after what was written.
    ///
    /// # Errors
    ///
    /// `Io` if the stream was already finished or reset.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.stream.finish().map_err(Error::io)
    }
}

/// The receiving half of a stream of one class, on one kind of connection.
#[derive(Debug)]
pub struct FrameReceiver {
    stream: RecvStream,
    class: StreamClass,
    connection: ConnectionKind,
    extensions: Extensions,
    closer: Option<iroh::endpoint::Connection>,
}

impl FrameReceiver {
    pub(crate) fn new(
        stream: RecvStream,
        class: StreamClass,
        connection: ConnectionKind,
        extensions: Extensions,
        closer: iroh::endpoint::Connection,
    ) -> Self {
        Self {
            stream,
            class,
            connection,
            extensions,
            closer: Some(closer),
        }
    }

    /// The stream's class.
    pub fn class(&self) -> StreamClass {
        self.class
    }

    /// The same stream, read as another class: a unidirectional stream's
    /// class is known only from its `Open`.
    pub(crate) fn with_class(mut self, class: StreamClass) -> Self {
        self.class = class;
        self
    }

    /// The next message, `None` once the stream ends between two frames.
    /// Ignorable messages (types 96 to 127 the receiver does not know) are
    /// dropped on the way.
    ///
    /// # Errors
    ///
    /// `read_frame`'s classes in the order of section 3.1, as
    /// [`Error::Protocol`], after which the connection is closed with the
    /// class's code; [`Error::Truncated`] for a stream that ends inside a
    /// frame; the connection's own failure otherwise.
    pub async fn receive(&mut self) -> Result<Option<Message>, Error> {
        loop {
            let Some(payload) = self.read_payload(self.class.cap()).await? else {
                return Ok(None);
            };
            match read_message(&payload, self.class, self.connection, self.extensions) {
                Ok(Some(message)) => return Ok(Some(message)),
                Ok(None) => continue,
                Err(class) => return Err(self.fail(class)),
            }
        }
    }

    /// Reads the next frame's payload whose prefix is at most `cap`, or
    /// `None` at the end of the stream between frames.
    pub(crate) async fn read_payload(&mut self, cap: usize) -> Result<Option<Vec<u8>>, Error> {
        let mut prefix = [0u8; 4];
        match self.stream.read_exact(&mut prefix).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(ReadExactError::FinishedEarly(_)) => return Err(Error::Truncated),
            Err(ReadExactError::ReadError(error)) => return Err(read_error(&error)),
        }
        // 1. The prefix is at most the class's cap, before anything is
        //    allocated.
        let length = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
        if length > cap {
            return Err(self.fail(frasil_crypto::ErrorClass::TooLarge.into()));
        }
        // The buffer grows with the bytes that arrive, at most doubling,
        // so a prefix alone holds no more than `FIRST_READ` on the stream.
        let mut payload = Vec::with_capacity(length.min(FIRST_READ));
        while payload.len() < length {
            let start = payload.len();
            let step = (length - start).min(start.max(FIRST_READ));
            payload.resize(start + step, 0);
            match self.stream.read_exact(&mut payload[start..]).await {
                Ok(()) => {}
                Err(ReadExactError::FinishedEarly(_)) => return Err(Error::Truncated),
                Err(ReadExactError::ReadError(error)) => return Err(read_error(&error)),
            }
        }
        Ok(Some(payload))
    }

    /// Closes the connection with the class's code (section 3.1: "a failure
    /// closes the connection with section 2.5's code").
    pub(crate) fn fail(&mut self, class: frasil_transport::TransportClass) -> Error {
        let closed = frasil_transport::Closed::of(class);
        if let Some(connection) = self.closer.take() {
            close(&connection, closed.code);
        }
        Error::Protocol(closed)
    }
}

/// Closes a connection with a code of section 2.5, its name as the reason.
pub(crate) fn close(connection: &iroh::endpoint::Connection, code: frasil_transport::Code) {
    let number = VarInt::from_u64(code.number()).unwrap_or(VarInt::from_u32(0));
    connection.close(number, code.name().as_bytes());
}

fn read_error(error: &iroh::endpoint::ReadError) -> Error {
    use iroh::endpoint::ReadError as E;
    match error {
        E::ConnectionLost(lost) => Error::of_connection(lost),
        other => Error::io(other),
    }
}

pub(crate) fn write_error(error: &iroh::endpoint::WriteError) -> Error {
    use iroh::endpoint::WriteError as E;
    match error {
        E::ConnectionLost(lost) => Error::of_connection(lost),
        other => Error::io(other),
    }
}
