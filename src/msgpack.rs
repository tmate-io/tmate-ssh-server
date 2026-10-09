//! Minimal MessagePack codec for the tmate wire protocol.
//!
//! Everything the host sends is untrusted, so decoding is bounded: a message
//! may not exceed `MAX_MESSAGE_SIZE` bytes or `MAX_DEPTH` levels of nesting,
//! and declared lengths are checked against the bytes actually present before
//! anything is allocated. Only the types tmate uses are accepted (nil, bool,
//! integers, floats, str/bin, arrays); maps and extension types are rejected.

use std::fmt;

/// Largest single message accepted from a peer. Snapshots sent on reconnect
/// are the biggest messages a well-behaved client produces.
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TooDeep,
    TooLarge,
    IntegerOutOfRange,
    Unsupported(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooDeep => write!(f, "message nested too deeply"),
            Error::TooLarge => write!(f, "message too large"),
            Error::IntegerOutOfRange => write!(f, "integer out of range"),
            Error::Unsupported(b) => write!(f, "unsupported msgpack type 0x{b:02x}"),
        }
    }
}

impl std::error::Error for Error {}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// Streaming decoder: feed bytes, pull complete values.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Bytes fed but not yet decoded (the start of an incomplete value, or
    /// whole values not pulled yet), leaving the decoder empty.
    pub fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Returns the next complete value, `Ok(None)` if more bytes are needed.
    pub fn next_value(&mut self) -> Result<Option<Value>, Error> {
        Ok(self.next_value_raw()?.map(|(v, _)| v))
    }

    /// Like `next_value`, also returning the bytes the value was decoded
    /// from, for forwarding a message verbatim.
    pub fn next_value_raw(&mut self) -> Result<Option<(Value, Vec<u8>)>, Error> {
        let len = match scan(&self.buf, 0, 0)? {
            Some(end) => end,
            None => {
                if self.buf.len() > MAX_MESSAGE_SIZE {
                    return Err(Error::TooLarge);
                }
                return Ok(None);
            }
        };
        if len > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        let (value, used) = decode_at(&self.buf[..len], 0, 0)?;
        debug_assert_eq!(used, len);
        let raw = self.buf.drain(..len).collect();
        Ok(Some((value, raw)))
    }
}

fn need(buf: &[u8], pos: usize, n: usize) -> Option<usize> {
    let end = pos.checked_add(n)?;
    (end <= buf.len()).then_some(end)
}

fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

/// Header of a msgpack item: how many payload bytes follow and how many
/// child items it contains.
struct Header {
    header_len: usize,
    payload_len: usize,
    children: usize,
}

fn header(buf: &[u8], pos: usize) -> Result<Option<Header>, Error> {
    let Some(&b) = buf.get(pos) else {
        return Ok(None);
    };
    let h = |header_len, payload_len, children| {
        Ok(Some(Header {
            header_len,
            payload_len,
            children,
        }))
    };
    // Reads an n-byte big-endian length that follows the type byte.
    let read_len = |n: usize| -> Option<usize> {
        let end = need(buf, pos + 1, n)?;
        usize::try_from(be_uint(&buf[pos + 1..end])).ok()
    };
    match b {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => h(1, 0, 0),
        0x90..=0x9f => h(1, 0, usize::from(b & 0x0f)),
        0xa0..=0xbf => h(1, usize::from(b & 0x1f), 0),
        0xcc | 0xd0 => h(1, 1, 0),
        0xcd | 0xd1 => h(1, 2, 0),
        0xce | 0xd2 | 0xca => h(1, 4, 0),
        0xcf | 0xd3 | 0xcb => h(1, 8, 0),
        0xc4 | 0xd9 => match read_len(1) {
            Some(n) => h(2, n, 0),
            None => Ok(None),
        },
        0xc5 | 0xda => match read_len(2) {
            Some(n) => h(3, n, 0),
            None => Ok(None),
        },
        0xc6 | 0xdb => match read_len(4) {
            Some(n) => h(5, n, 0),
            None => Ok(None),
        },
        0xdc => match read_len(2) {
            Some(n) => h(3, 0, n),
            None => Ok(None),
        },
        0xdd => match read_len(4) {
            Some(n) => h(5, 0, n),
            None => Ok(None),
        },
        other => Err(Error::Unsupported(other)),
    }
}

/// Finds the end of the item starting at `pos` without allocating.
fn scan(buf: &[u8], pos: usize, depth: usize) -> Result<Option<usize>, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::TooDeep);
    }
    let Some(h) = header(buf, pos)? else {
        return Ok(None);
    };
    if h.payload_len > MAX_MESSAGE_SIZE || h.children > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge);
    }
    let mut end = pos + h.header_len + h.payload_len;
    if end > MAX_MESSAGE_SIZE + pos {
        return Err(Error::TooLarge);
    }
    if end > buf.len() {
        return Ok(None);
    }
    for _ in 0..h.children {
        match scan(buf, end, depth + 1)? {
            Some(next) => end = next,
            None => return Ok(None),
        }
        if end - pos > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
    }
    Ok(Some(end))
}

/// Decodes an item that `scan` has already proven complete.
fn decode_at(buf: &[u8], pos: usize, depth: usize) -> Result<(Value, usize), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::TooDeep);
    }
    let h = header(buf, pos)?.ok_or(Error::TooLarge)?;
    let start = pos + h.header_len;
    let payload = &buf[start..start + h.payload_len];
    let next = start + h.payload_len;
    let b = buf[pos];
    let value = match b {
        0x00..=0x7f => Value::Int(i64::from(b)),
        0xe0..=0xff => Value::Int(i64::from(b as i8)),
        0xc0 => Value::Nil,
        0xc2 => Value::Bool(false),
        0xc3 => Value::Bool(true),
        0xcc..=0xcf => {
            let v = be_uint(payload);
            Value::Int(i64::try_from(v).map_err(|_| Error::IntegerOutOfRange)?)
        }
        0xd0 => Value::Int(i64::from(payload[0] as i8)),
        0xd1 => Value::Int(i64::from(i16::from_be_bytes([payload[0], payload[1]]))),
        0xd2 => Value::Int(i64::from(i32::from_be_bytes(payload.try_into().unwrap()))),
        0xd3 => Value::Int(i64::from_be_bytes(payload.try_into().unwrap())),
        0xca => Value::Float(f64::from(f32::from_be_bytes(payload.try_into().unwrap()))),
        0xcb => Value::Float(f64::from_be_bytes(payload.try_into().unwrap())),
        0xa0..=0xbf | 0xd9..=0xdb | 0xc4..=0xc6 => Value::Bytes(payload.to_vec()),
        _ => {
            // Arrays: `scan` bounded the element count by the bytes present.
            let mut items = Vec::with_capacity(h.children.min(buf.len() - next));
            let mut cur = next;
            for _ in 0..h.children {
                let (v, n) = decode_at(buf, cur, depth + 1)?;
                items.push(v);
                cur = n;
            }
            return Ok((Value::Array(items), cur));
        }
    };
    Ok((value, next))
}

/// Encoder for messages sent to the host.
#[derive(Default)]
pub struct Encoder {
    pub buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn array(&mut self, len: usize) -> &mut Self {
        match len {
            0..=15 => self.buf.push(0x90 | len as u8),
            16..=0xffff => {
                self.buf.push(0xdc);
                self.buf.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                self.buf.push(0xdd);
                self.buf.extend_from_slice(&(len as u32).to_be_bytes());
            }
        }
        self
    }

    pub fn int(&mut self, v: i64) -> &mut Self {
        if (0..=0x7f).contains(&v) {
            self.buf.push(v as u8);
        } else if (-32..0).contains(&v) {
            self.buf.push(v as i8 as u8);
        } else if v >= 0 {
            self.uint(v as u64);
        } else if v >= i64::from(i8::MIN) {
            self.buf.push(0xd0);
            self.buf.push(v as i8 as u8);
        } else if v >= i64::from(i16::MIN) {
            self.buf.push(0xd1);
            self.buf.extend_from_slice(&(v as i16).to_be_bytes());
        } else if v >= i64::from(i32::MIN) {
            self.buf.push(0xd2);
            self.buf.extend_from_slice(&(v as i32).to_be_bytes());
        } else {
            self.buf.push(0xd3);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn uint(&mut self, v: u64) -> &mut Self {
        if v <= 0x7f {
            self.buf.push(v as u8);
        } else if v <= 0xff {
            self.buf.push(0xcc);
            self.buf.push(v as u8);
        } else if v <= 0xffff {
            self.buf.push(0xcd);
            self.buf.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.buf.push(0xce);
            self.buf.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.buf.push(0xcf);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.raw_str(s.as_bytes())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// Raw bytes (msgpack `bin`); decoded as `Value::Bytes` like a string.
    pub fn bin(&mut self, b: &[u8]) -> &mut Self {
        let len = b.len();
        match len {
            0..=0xff => {
                self.buf.push(0xc4);
                self.buf.push(len as u8);
            }
            0x100..=0xffff => {
                self.buf.push(0xc5);
                self.buf.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                self.buf.push(0xc6);
                self.buf.extend_from_slice(&(len as u32).to_be_bytes());
            }
        }
        self.buf.extend_from_slice(b);
        self
    }

    #[allow(dead_code)]
    pub fn nil(&mut self) -> &mut Self {
        self.buf.push(0xc0);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0xc3 } else { 0xc2 });
        self
    }

    pub fn float(&mut self, v: f64) -> &mut Self {
        self.buf.push(0xcb);
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Re-encodes a decoded value. Bytes become `str`, which is what the
    /// peers that send us values to forward (the backend) use for them.
    pub fn value(&mut self, v: &Value) -> &mut Self {
        match v {
            Value::Nil => self.nil(),
            Value::Bool(b) => self.bool(*b),
            Value::Int(i) => self.int(*i),
            Value::Float(f) => self.float(*f),
            Value::Bytes(b) => self.raw_str(b),
            Value::Array(items) => {
                self.array(items.len());
                for item in items {
                    self.value(item);
                }
                self
            }
        }
    }

    /// A `str` whose bytes need not be UTF-8.
    fn raw_str(&mut self, s: &[u8]) -> &mut Self {
        let len = s.len();
        match len {
            0..=31 => self.buf.push(0xa0 | len as u8),
            32..=0xff => {
                self.buf.push(0xd9);
                self.buf.push(len as u8);
            }
            0x100..=0xffff => {
                self.buf.push(0xda);
                self.buf.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                self.buf.push(0xdb);
                self.buf.extend_from_slice(&(len as u32).to_be_bytes());
            }
        }
        self.buf.extend_from_slice(s);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(bytes: &[u8]) -> Result<Vec<Value>, Error> {
        let mut d = Decoder::new();
        d.feed(bytes);
        let mut out = vec![];
        while let Some(v) = d.next_value()? {
            out.push(v);
        }
        Ok(out)
    }

    #[test]
    fn roundtrip() {
        let mut e = Encoder::new();
        e.array(6)
            .int(5)
            .int(-1)
            .int(-200)
            .uint(u64::from(u32::MAX) + 7)
            .str("hello")
            .array(2)
            .nil()
            .bool(true);
        let v = decode_all(&e.buf).unwrap();
        assert_eq!(
            v,
            vec![Value::Array(vec![
                Value::Int(5),
                Value::Int(-1),
                Value::Int(-200),
                Value::Int(i64::from(u32::MAX) + 7),
                Value::Bytes(b"hello".to_vec()),
                Value::Array(vec![Value::Nil, Value::Bool(true)]),
            ])]
        );
    }

    #[test]
    fn incremental() {
        let mut e = Encoder::new();
        e.array(2).int(2).str(&"x".repeat(1000));
        let mut d = Decoder::new();
        for chunk in e.buf.chunks(7) {
            assert_eq!(d.next_value().unwrap(), None);
            d.feed(chunk);
        }
        assert!(d.next_value().unwrap().is_some());
        assert_eq!(d.next_value().unwrap(), None);
    }

    #[test]
    fn huge_declared_lengths_do_not_allocate() {
        // array32 claiming 4 billion elements, with nothing following.
        assert!(matches!(
            decode_all(&[0xdd, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::TooLarge)
        ));
        // bin32 claiming 4 GiB.
        assert!(matches!(
            decode_all(&[0xc6, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::TooLarge)
        ));
        // A plausible-size array that is simply incomplete waits for more.
        assert_eq!(decode_all(&[0xdc, 0x00, 0x10]).unwrap(), vec![]);
    }

    #[test]
    fn depth_limit() {
        let bytes = vec![0x91; MAX_DEPTH + 5];
        assert!(matches!(decode_all(&bytes), Err(Error::TooDeep)));
    }

    #[test]
    fn rejects_maps_and_ext() {
        assert!(matches!(decode_all(&[0x80]), Err(Error::Unsupported(0x80))));
        assert!(matches!(
            decode_all(&[0xd4, 0, 0]),
            Err(Error::Unsupported(0xd4))
        ));
    }

    #[test]
    fn raw_bytes_and_value_reencoding() {
        let mut e = Encoder::new();
        e.array(3).int(2).int(0).bin(b"\x1b[Hhi");
        e.array(2).int(0).str("x");
        let first_len = e.buf.len() - 4;
        let mut d = Decoder::new();
        d.feed(&e.buf);
        let (v, raw) = d.next_value_raw().unwrap().unwrap();
        assert_eq!(raw, e.buf[..first_len]);
        assert_eq!(
            v,
            Value::Array(vec![
                Value::Int(2),
                Value::Int(0),
                Value::Bytes(b"\x1b[Hhi".to_vec())
            ])
        );
        // Re-encoding a value decodes to the same value (bin becomes str).
        let mut e2 = Encoder::new();
        e2.value(&v);
        assert_eq!(decode_all(&e2.buf).unwrap(), vec![v]);
        let nested = Value::Array(vec![
            Value::Nil,
            Value::Bool(false),
            Value::Int(-70000),
            Value::Float(1.5),
            Value::Bytes(vec![0xff; 300]),
            Value::Array(vec![]),
        ]);
        let mut e3 = Encoder::new();
        e3.value(&nested);
        assert_eq!(decode_all(&e3.buf).unwrap(), vec![nested]);
    }

    #[test]
    fn uint64_overflow_rejected() {
        assert!(matches!(
            decode_all(&[0xcf, 0xff, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::IntegerOutOfRange)
        ));
    }
}
