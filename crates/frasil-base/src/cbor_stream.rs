//! Incremental tokens for the deterministic CBOR subset.
use crate::cbor::{Malformed, Reader};

/// A complete scalar or a definite container head.
pub enum Token<'a> {
    /// An unsigned integer.
    Unsigned(u64),
    /// A byte string.
    Bytes(&'a [u8]),
    /// UTF-8 text.
    Text(&'a str),
    /// An array's item count.
    Array(u64),
    /// A map's pair count. Consumers check unsigned, ascending keys.
    Map(u64),
    /// The head of a byte string (or, with `text`, a text string) longer
    /// than the reader's item limit. It counts as one complete item; its
    /// content follows as [`Token::Part`]s and is never held whole.
    Long {
        /// Whether it is text, whose content is checked as UTF-8.
        text: bool,
        /// Its length in bytes.
        len: u64,
    },
    /// The next piece of a long string's content, `last` when it ends it.
    Part {
        /// The piece.
        bytes: &'a [u8],
        /// Whether the string ends with this piece.
        last: bool,
    },
}

/// The rest of a long string being read.
struct Long {
    remaining: u64,
    text: bool,
    /// An incomplete UTF-8 sequence carried to the next piece.
    carry: [u8; 4],
    carried: usize,
}

impl Long {
    /// Checks the next piece of text as UTF-8, carrying an incomplete
    /// sequence at its end, as a check of the whole string would.
    fn check(&mut self, mut piece: &[u8]) -> Result<(), Malformed> {
        if !self.text {
            return Ok(());
        }
        if self.carried > 0 {
            let width = match self.carry[0] {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                _ => 4,
            };
            let take = (width - self.carried).min(piece.len());
            self.carry[self.carried..self.carried + take].copy_from_slice(&piece[..take]);
            self.carried += take;
            piece = &piece[take..];
            if self.carried < width {
                // Still a prefix of one character: check it as one.
                return match std::str::from_utf8(&self.carry[..self.carried]) {
                    Err(e) if e.error_len().is_none() => Ok(()),
                    _ => Err(Malformed),
                };
            }
            std::str::from_utf8(&self.carry[..width]).map_err(|_| Malformed)?;
            self.carried = 0;
        }
        match std::str::from_utf8(piece) {
            Ok(_) => Ok(()),
            Err(e) if e.error_len().is_none() => {
                let tail = &piece[e.valid_up_to()..];
                self.carry[..tail.len()].copy_from_slice(tail);
                self.carried = tail.len();
                Ok(())
            }
            Err(_) => Err(Malformed),
        }
    }
}

/// A push decoder, retaining unread bytes and container counts only. A
/// string longer than its item limit is passed on in pieces, so the bytes
/// it holds are at most one pushed input and one item within the limit.
pub struct PushReader {
    buffer: Vec<u8>,
    offset: usize,
    stack: Vec<u64>,
    started: bool,
    max_depth: usize,
    max_item: usize,
    long: Option<Long>,
    failed: bool,
}
impl PushReader {
    /// Creates a decoder with the top-level item at depth zero, which holds
    /// every string whole.
    pub fn new(max_depth: usize) -> Self {
        Self::with_item_limit(max_depth, usize::MAX)
    }
    /// [`Self::new`], passing on a byte or text string longer than
    /// `max_item` bytes as [`Token::Long`] and its [`Token::Part`]s.
    pub fn with_item_limit(max_depth: usize, max_item: usize) -> Self {
        Self {
            buffer: Vec::new(),
            offset: 0,
            stack: Vec::new(),
            started: false,
            max_depth,
            max_item,
            long: None,
            failed: false,
        }
    }
    /// Supplies more input, discarding bytes already consumed.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.drain(..self.offset);
        self.offset = 0;
        self.buffer.extend_from_slice(bytes);
    }
    /// Next complete token in shortest form, definite length; `None` needs more bytes.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Token<'_>>, Malformed> {
        if self.failed {
            return Err(Malformed);
        }
        if let Some(long) = &mut self.long {
            let start = self.offset;
            let available = self.buffer.len() - start;
            if available == 0 {
                return Ok(None);
            }
            let take = usize::try_from(long.remaining).map_or(available, |r| r.min(available));
            if long.check(&self.buffer[start..start + take]).is_err() {
                self.failed = true;
                return Err(Malformed);
            }
            long.remaining -= take as u64;
            let last = long.remaining == 0;
            if last {
                let carried = long.carried;
                self.long = None;
                if carried > 0 {
                    self.failed = true;
                    return Err(Malformed);
                }
            }
            self.offset += take;
            return Ok(Some(Token::Part {
                bytes: &self.buffer[start..start + take],
                last,
            }));
        }
        let result = self.advance();
        if result.is_err() {
            self.failed = true;
        }
        result?;
        let data = &self.buffer[self.offset..];
        if data.is_empty() {
            return Ok(None);
        }
        // advance validated the head and payload, without borrowing the output.
        let major = data[0] >> 5;
        let needed = match data[0] & 31 {
            0..=23 => 1,
            24 => 2,
            25 => 3,
            26 => 5,
            27 => 9,
            _ => return Err(Malformed),
        };
        if data.len() < needed {
            return Ok(None);
        }
        let mut reader = Reader::new(data);
        let n = reader.head(major)?;
        let head = data.len() - reader.remaining().len();
        let long = matches!(major, 2 | 3) && n > self.max_item as u64;
        let len = if matches!(major, 2 | 3) && !long {
            usize::try_from(n).map_err(|_| Malformed)?
        } else {
            0
        };
        if data.len() < head + len {
            return Ok(None);
        }
        self.offset += head + len;
        if let Some(left) = self.stack.last_mut() {
            *left -= 1;
        }
        self.started = true;
        let children = match major {
            4 => n,
            5 => n.checked_mul(2).ok_or(Malformed)?,
            _ => 0,
        };
        if children > 0 {
            self.stack.push(children);
        }
        while self.stack.last() == Some(&0) {
            self.stack.pop();
        }
        if long {
            self.long = Some(Long {
                remaining: n,
                text: major == 3,
                carry: [0; 4],
                carried: 0,
            });
            return Ok(Some(Token::Long {
                text: major == 3,
                len: n,
            }));
        }
        Ok(Some(match major {
            0 => Token::Unsigned(n),
            2 => Token::Bytes(&data[head..head + len]),
            3 => Token::Text(std::str::from_utf8(&data[head..head + len]).map_err(|_| Malformed)?),
            4 => Token::Array(n),
            5 => Token::Map(n),
            _ => return Err(Malformed),
        }))
    }
    fn advance(&mut self) -> Result<(), Malformed> {
        let data = &self.buffer[self.offset..];
        if data.is_empty() {
            return Ok(());
        }
        if (self.started && self.stack.is_empty()) || self.stack.len() > self.max_depth {
            return Err(Malformed);
        }
        let major = data[0] >> 5;
        if !matches!(major, 0 | 2..=5) {
            return Err(Malformed);
        }
        let needed = match data[0] & 31 {
            0..=23 => 1,
            24 => 2,
            25 => 3,
            26 => 5,
            27 => 9,
            _ => return Err(Malformed),
        };
        if data.len() < needed {
            return Ok(());
        }
        let mut reader = Reader::new(data);
        let n = reader.head(major)?;
        if major == 5 && n.checked_mul(2).is_none() {
            return Err(Malformed);
        }
        if matches!(major, 2 | 3) && n <= self.max_item as u64 {
            let len = usize::try_from(n).map_err(|_| Malformed)?;
            let end = needed.checked_add(len).ok_or(Malformed)?;
            if major == 3 && end <= data.len() {
                std::str::from_utf8(&data[needed..end]).map_err(|_| Malformed)?;
            }
        }
        Ok(())
    }
    /// Exactly one complete top-level item and no bytes left.
    pub fn finish(&self) -> Result<(), Malformed> {
        if !self.failed
            && self.started
            && self.long.is_none()
            && self.stack.is_empty()
            && self.offset == self.buffer.len()
        {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{self, Value};

    /// Reads `data` in pieces of `chunk` bytes, with strings over `limit`
    /// passed on in parts; whether it reads, and the largest buffer held.
    fn read(data: &[u8], chunk: usize, limit: usize) -> (bool, usize) {
        let mut reader = PushReader::with_item_limit(cbor::MAX_DEPTH, limit);
        let mut held = 0;
        for piece in data.chunks(chunk.max(1)) {
            reader.push(piece);
            held = held.max(reader.buffer.len());
            loop {
                match reader.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return (false, held),
                }
            }
        }
        (reader.finish().is_ok(), held)
    }

    #[test]
    fn long_strings_read_as_whole_ones_do_without_being_held() {
        let text = "aé€😀".repeat(500);
        let mut bad = Value::Text(text.clone()).encode();
        // A continuation byte where a character starts.
        let at = bad.len() - 3;
        bad[at] = 0x80;
        // Text whose last character is cut short.
        let mut cut = Vec::new();
        cbor::head(&mut cut, 3, 2002);
        cut.extend_from_slice(&[b'a'; 2000]);
        cut.extend_from_slice(&[0xe2, 0x82]);
        let cases = [
            Value::Text(text.clone()).encode(),
            Value::Bytes(vec![7; 5000]).encode(),
            Value::Array(vec![Value::Bytes(vec![1; 3000]), Value::Unsigned(1)]).encode(),
            bad,
            cut,
        ];
        for data in &cases {
            let whole = cbor::decode(data).is_ok();
            for chunk in [1, 2, 3, 5, 64, 1000, data.len()] {
                let (ok, held) = read(data, chunk, 64);
                assert_eq!(ok, whole, "chunk {chunk}");
                assert!(held <= chunk + 64 + 9, "held {held} at chunk {chunk}");
            }
        }
    }
}
