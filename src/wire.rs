//! Messages between the gateway and a session worker.
//!
//! On Linux every session's hub runs in its own sandboxed process (see
//! `worker.rs`); the gateway keeps the SSH connections and forwards the raw
//! bytes the host sends plus the viewers' events over a `socketpair`, and
//! the worker answers with the bytes to write to each connection. Frames are
//! a 4-byte big-endian length followed by one msgpack array
//! `[tag, fields…]`, encoded and decoded with the same codec the tmate
//! protocol uses. The worker side is untrusted once it has processed host
//! bytes, so the gateway decodes its frames with the same care as a host's.
//!
//! With a backend (`-w`), the session's TCP connection to it stays in the
//! gateway (workers have no network): what the backend sends is forwarded
//! as `BackendData`, and what the worker wants sent to it comes back as
//! `ToBackend`.

use std::fmt;

use crate::hub::ViewerId;
use crate::msgpack::{self, Decoder, Encoder, Value};
use crate::render::Size;
use crate::session::{Access, Tokens};

/// Largest frame either side accepts. Host messages are at most
/// `msgpack::MAX_MESSAGE_SIZE`; larger payloads are split into `CHUNK`s.
pub const MAX_FRAME: usize = msgpack::MAX_MESSAGE_SIZE;

/// Payloads to a connection are split into pieces of this size so no frame
/// comes near `MAX_FRAME`.
pub const CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToWorker {
    /// First message: who the host is and what to tell it.
    Hello {
        peer_ip: String,
        /// The host's key, OpenSSH one-line form, if it used one.
        host_pubkey: Option<String>,
        advertised_host: String,
        advertised_port: u16,
        keys_required: bool,
        tokens: Tokens,
        /// Signed by the gateway for `tokens` (`tmate_reconnection_data`).
        reconnection_data: String,
        /// The gateway holds a backend connection for this session.
        backend: bool,
    },
    HostData(Vec<u8>),
    HostGone,
    ViewerAttach {
        id: ViewerId,
        ip: String,
        pubkey: Option<String>,
        access: Access,
        size: Size,
    },
    ViewerInput {
        id: ViewerId,
        data: Vec<u8>,
    },
    ViewerResize {
        id: ViewerId,
        size: Size,
    },
    ViewerDetach(ViewerId),
    /// The gateway's verdict on a `Reconnect`: the tokens to continue
    /// under as a fresh session (with their signed reconnection data), or
    /// none if the data was not ours.
    ReconnectResult {
        tokens: Option<Tokens>,
        reconnection_data: String,
    },
    /// A reconnecting host took the session over; its remaining bytes
    /// follow as `HostData`. Output for it carries `epoch`.
    HostAdopted {
        epoch: u64,
        peer_ip: String,
        client_version: String,
    },
    /// Bytes from the backend connection.
    BackendData(Vec<u8>),
    /// The backend connection closed or failed.
    BackendGone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToGateway {
    /// Sent once the worker is locked down, before it reads anything.
    Ready {
        sandbox: String,
        level: u8,
    },
    ToHost {
        epoch: u64,
        data: Vec<u8>,
    },
    CloseHost {
        epoch: u64,
    },
    ToViewer {
        id: ViewerId,
        data: Vec<u8>,
    },
    CloseViewer(ViewerId),
    Register(Tokens),
    Unregister(Tokens),
    AuthorizedKeys {
        enabled: bool,
        keys: Vec<String>,
    },
    /// The host sent RECONNECT; `rest` is what followed it, undecoded.
    Reconnect {
        data: String,
        rest: Vec<u8>,
        client_version: String,
    },
    /// Bytes for the backend connection.
    ToBackend(Vec<u8>),
    /// The session is done with its backend connection.
    CloseBackend,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    FrameTooLarge(usize),
    Msgpack(msgpack::Error),
    Malformed(&'static str),
    UnknownTag(i64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FrameTooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
            Error::Msgpack(e) => write!(f, "bad msgpack: {e}"),
            Error::Malformed(what) => write!(f, "malformed message: {what}"),
            Error::UnknownTag(t) => write!(f, "unknown message tag {t}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<msgpack::Error> for Error {
    fn from(e: msgpack::Error) -> Self {
        Error::Msgpack(e)
    }
}

/// Splits a byte stream into frames.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next complete frame's payload, `Ok(None)` if more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME {
            return Err(Error::FrameTooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let payload = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(payload))
    }
}

fn frame(mut enc: Encoder) -> Vec<u8> {
    let payload = enc.take();
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Decodes one frame's payload into a msgpack value.
fn decode_payload(payload: &[u8]) -> Result<Vec<Value>, Error> {
    let mut dec = Decoder::new();
    dec.feed(payload);
    let value = dec
        .next_value()?
        .ok_or(Error::Malformed("truncated payload"))?;
    if !dec.take_pending().is_empty() {
        return Err(Error::Malformed("trailing bytes"));
    }
    match value {
        Value::Array(items) if !items.is_empty() => Ok(items),
        _ => Err(Error::Malformed("not a tagged array")),
    }
}

fn int(v: Option<&Value>) -> Result<i64, Error> {
    v.and_then(Value::as_int)
        .ok_or(Error::Malformed("expected integer"))
}

fn uint(v: Option<&Value>) -> Result<u64, Error> {
    u64::try_from(int(v)?).map_err(|_| Error::Malformed("expected unsigned integer"))
}

fn u16_of(v: Option<&Value>) -> Result<u16, Error> {
    u16::try_from(int(v)?).map_err(|_| Error::Malformed("integer out of u16 range"))
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, Error> {
    v.and_then(Value::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or(Error::Malformed("expected bytes"))
}

fn string(v: Option<&Value>) -> Result<String, Error> {
    String::from_utf8(bytes(v)?).map_err(|_| Error::Malformed("expected utf-8 string"))
}

fn boolean(v: Option<&Value>) -> Result<bool, Error> {
    match v {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(Error::Malformed("expected bool")),
    }
}

fn viewer(v: Option<&Value>) -> Result<ViewerId, Error> {
    Ok(ViewerId::from_raw(uint(v)?))
}

fn size(cols: Option<&Value>, rows: Option<&Value>) -> Result<Size, Error> {
    Ok(Size {
        cols: u16_of(cols)?,
        rows: u16_of(rows)?,
    })
}

fn tokens(rw: Option<&Value>, ro: Option<&Value>) -> Result<Tokens, Error> {
    let t = Tokens {
        rw: string(rw)?,
        ro: string(ro)?,
    };
    // A backend may rename a session to a named token.
    if !crate::session::is_acceptable_token(&t.rw) || !crate::session::is_acceptable_token(&t.ro) {
        return Err(Error::Malformed("invalid token"));
    }
    Ok(t)
}

fn opt_string(v: Option<&Value>) -> Result<Option<String>, Error> {
    match v {
        Some(Value::Nil) => Ok(None),
        other => string(other).map(Some),
    }
}

fn string_list(v: Option<&Value>) -> Result<Vec<String>, Error> {
    v.and_then(Value::as_array)
        .ok_or(Error::Malformed("expected array"))?
        .iter()
        .map(|s| string(Some(s)))
        .collect()
}

const HELLO: i64 = 1;
const HOST_DATA: i64 = 2;
const HOST_GONE: i64 = 3;
const VIEWER_ATTACH: i64 = 4;
const VIEWER_INPUT: i64 = 5;
const VIEWER_RESIZE: i64 = 6;
const VIEWER_DETACH: i64 = 7;
const RECONNECT_RESULT: i64 = 8;
const HOST_ADOPTED: i64 = 9;
const BACKEND_DATA: i64 = 10;
const BACKEND_GONE: i64 = 11;

const READY: i64 = 101;
const TO_HOST: i64 = 102;
const CLOSE_HOST: i64 = 103;
const TO_VIEWER: i64 = 104;
const CLOSE_VIEWER: i64 = 105;
const REGISTER: i64 = 106;
const UNREGISTER: i64 = 107;
const AUTHORIZED_KEYS: i64 = 108;
const RECONNECT: i64 = 109;
const TO_BACKEND: i64 = 110;
const CLOSE_BACKEND: i64 = 111;

impl ToWorker {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        match self {
            ToWorker::Hello {
                peer_ip,
                host_pubkey,
                advertised_host,
                advertised_port,
                keys_required,
                tokens,
                reconnection_data,
                backend,
            } => {
                enc.array(10).int(HELLO).str(peer_ip);
                match host_pubkey {
                    Some(k) => enc.str(k),
                    None => enc.nil(),
                };
                enc.str(advertised_host)
                    .uint(u64::from(*advertised_port))
                    .bool(*keys_required)
                    .str(&tokens.rw)
                    .str(&tokens.ro)
                    .str(reconnection_data)
                    .bool(*backend);
            }
            ToWorker::HostData(data) => {
                enc.array(2).int(HOST_DATA).bin(data);
            }
            ToWorker::HostGone => {
                enc.array(1).int(HOST_GONE);
            }
            ToWorker::ViewerAttach {
                id,
                ip,
                pubkey,
                access,
                size,
            } => {
                enc.array(7).int(VIEWER_ATTACH).uint(id.raw()).str(ip);
                match pubkey {
                    Some(k) => enc.str(k),
                    None => enc.nil(),
                };
                enc.int(match access {
                    Access::ReadWrite => 0,
                    Access::ReadOnly => 1,
                })
                .uint(u64::from(size.cols))
                .uint(u64::from(size.rows));
            }
            ToWorker::ViewerInput { id, data } => {
                enc.array(3).int(VIEWER_INPUT).uint(id.raw()).bin(data);
            }
            ToWorker::ViewerResize { id, size } => {
                enc.array(4)
                    .int(VIEWER_RESIZE)
                    .uint(id.raw())
                    .uint(u64::from(size.cols))
                    .uint(u64::from(size.rows));
            }
            ToWorker::ViewerDetach(id) => {
                enc.array(2).int(VIEWER_DETACH).uint(id.raw());
            }
            ToWorker::ReconnectResult {
                tokens,
                reconnection_data,
            } => match tokens {
                Some(t) => {
                    enc.array(4)
                        .int(RECONNECT_RESULT)
                        .str(&t.rw)
                        .str(&t.ro)
                        .str(reconnection_data);
                }
                None => {
                    enc.array(1).int(RECONNECT_RESULT);
                }
            },
            ToWorker::HostAdopted {
                epoch,
                peer_ip,
                client_version,
            } => {
                enc.array(4)
                    .int(HOST_ADOPTED)
                    .uint(*epoch)
                    .str(peer_ip)
                    .str(client_version);
            }
            ToWorker::BackendData(data) => {
                enc.array(2).int(BACKEND_DATA).bin(data);
            }
            ToWorker::BackendGone => {
                enc.array(1).int(BACKEND_GONE);
            }
        }
        frame(enc)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let items = decode_payload(payload)?;
        let tag = int(items.first())?;
        let f = |i: usize| items.get(i);
        Ok(match tag {
            HELLO => ToWorker::Hello {
                peer_ip: string(f(1))?,
                host_pubkey: opt_string(f(2))?,
                advertised_host: string(f(3))?,
                advertised_port: u16_of(f(4))?,
                keys_required: boolean(f(5))?,
                tokens: tokens(f(6), f(7))?,
                reconnection_data: string(f(8))?,
                backend: boolean(f(9))?,
            },
            HOST_DATA => ToWorker::HostData(bytes(f(1))?),
            HOST_GONE => ToWorker::HostGone,
            VIEWER_ATTACH => ToWorker::ViewerAttach {
                id: viewer(f(1))?,
                ip: string(f(2))?,
                pubkey: opt_string(f(3))?,
                access: match int(f(4))? {
                    0 => Access::ReadWrite,
                    1 => Access::ReadOnly,
                    _ => return Err(Error::Malformed("bad access")),
                },
                size: size(f(5), f(6))?,
            },
            VIEWER_INPUT => ToWorker::ViewerInput {
                id: viewer(f(1))?,
                data: bytes(f(2))?,
            },
            VIEWER_RESIZE => ToWorker::ViewerResize {
                id: viewer(f(1))?,
                size: size(f(2), f(3))?,
            },
            VIEWER_DETACH => ToWorker::ViewerDetach(viewer(f(1))?),
            RECONNECT_RESULT => {
                if items.len() == 1 {
                    ToWorker::ReconnectResult {
                        tokens: None,
                        reconnection_data: String::new(),
                    }
                } else {
                    ToWorker::ReconnectResult {
                        tokens: Some(tokens(f(1), f(2))?),
                        reconnection_data: string(f(3))?,
                    }
                }
            }
            HOST_ADOPTED => ToWorker::HostAdopted {
                epoch: uint(f(1))?,
                peer_ip: string(f(2))?,
                client_version: string(f(3))?,
            },
            BACKEND_DATA => ToWorker::BackendData(bytes(f(1))?),
            BACKEND_GONE => ToWorker::BackendGone,
            other => return Err(Error::UnknownTag(other)),
        })
    }
}

impl ToGateway {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        match self {
            ToGateway::Ready { sandbox, level } => {
                enc.array(3).int(READY).str(sandbox).uint(u64::from(*level));
            }
            ToGateway::ToHost { epoch, data } => {
                enc.array(3).int(TO_HOST).uint(*epoch).bin(data);
            }
            ToGateway::CloseHost { epoch } => {
                enc.array(2).int(CLOSE_HOST).uint(*epoch);
            }
            ToGateway::ToViewer { id, data } => {
                enc.array(3).int(TO_VIEWER).uint(id.raw()).bin(data);
            }
            ToGateway::CloseViewer(id) => {
                enc.array(2).int(CLOSE_VIEWER).uint(id.raw());
            }
            ToGateway::Register(t) => {
                enc.array(3).int(REGISTER).str(&t.rw).str(&t.ro);
            }
            ToGateway::Unregister(t) => {
                enc.array(3).int(UNREGISTER).str(&t.rw).str(&t.ro);
            }
            ToGateway::AuthorizedKeys { enabled, keys } => {
                enc.array(3)
                    .int(AUTHORIZED_KEYS)
                    .bool(*enabled)
                    .array(keys.len());
                for k in keys {
                    enc.str(k);
                }
            }
            ToGateway::Reconnect {
                data,
                rest,
                client_version,
            } => {
                enc.array(4)
                    .int(RECONNECT)
                    .str(data)
                    .bin(rest)
                    .str(client_version);
            }
            ToGateway::ToBackend(data) => {
                enc.array(2).int(TO_BACKEND).bin(data);
            }
            ToGateway::CloseBackend => {
                enc.array(1).int(CLOSE_BACKEND);
            }
        }
        frame(enc)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let items = decode_payload(payload)?;
        let tag = int(items.first())?;
        let f = |i: usize| items.get(i);
        Ok(match tag {
            READY => ToGateway::Ready {
                sandbox: string(f(1))?,
                level: u8::try_from(uint(f(2))?).map_err(|_| Error::Malformed("level"))?,
            },
            TO_HOST => ToGateway::ToHost {
                epoch: uint(f(1))?,
                data: bytes(f(2))?,
            },
            CLOSE_HOST => ToGateway::CloseHost { epoch: uint(f(1))? },
            TO_VIEWER => ToGateway::ToViewer {
                id: viewer(f(1))?,
                data: bytes(f(2))?,
            },
            CLOSE_VIEWER => ToGateway::CloseViewer(viewer(f(1))?),
            REGISTER => ToGateway::Register(tokens(f(1), f(2))?),
            UNREGISTER => ToGateway::Unregister(tokens(f(1), f(2))?),
            AUTHORIZED_KEYS => ToGateway::AuthorizedKeys {
                enabled: boolean(f(1))?,
                keys: string_list(f(2))?,
            },
            RECONNECT => ToGateway::Reconnect {
                data: string(f(1))?,
                rest: bytes(f(2))?,
                client_version: string(f(3))?,
            },
            TO_BACKEND => ToGateway::ToBackend(bytes(f(1))?),
            CLOSE_BACKEND => ToGateway::CloseBackend,
            other => return Err(Error::UnknownTag(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_worker(msg: ToWorker) {
        let bytes = msg.encode();
        let mut framer = Framer::new();
        framer.feed(&bytes);
        let payload = framer.next_frame().unwrap().expect("one frame");
        assert_eq!(ToWorker::decode(&payload).unwrap(), msg);
        assert_eq!(framer.next_frame().unwrap(), None);
    }

    fn roundtrip_gateway(msg: ToGateway) {
        let bytes = msg.encode();
        let mut framer = Framer::new();
        framer.feed(&bytes);
        let payload = framer.next_frame().unwrap().expect("one frame");
        assert_eq!(ToGateway::decode(&payload).unwrap(), msg);
    }

    #[test]
    fn every_message_roundtrips() {
        let tokens = Tokens::generate();
        let id = ViewerId::from_raw(7);
        let size = Size {
            cols: 132,
            rows: 43,
        };
        for msg in [
            ToWorker::Hello {
                peer_ip: "203.0.113.9".into(),
                host_pubkey: None,
                advertised_host: "tmate.example".into(),
                advertised_port: 22,
                keys_required: true,
                tokens: tokens.clone(),
                reconnection_data: "payload|sig".into(),
                backend: false,
            },
            ToWorker::Hello {
                peer_ip: "203.0.113.9".into(),
                host_pubkey: Some("ssh-ed25519 AAAA".into()),
                advertised_host: "tmate.example".into(),
                advertised_port: 22,
                keys_required: false,
                tokens: Tokens {
                    rw: "acme/demo".into(),
                    ro: "ro-acme/demo".into(),
                },
                reconnection_data: String::new(),
                backend: true,
            },
            ToWorker::HostData(vec![0x93, 1, 2, 3]),
            ToWorker::HostData(vec![0xff; 70_000]),
            ToWorker::HostGone,
            ToWorker::ViewerAttach {
                id,
                ip: "10.0.0.1".into(),
                pubkey: None,
                access: Access::ReadOnly,
                size,
            },
            ToWorker::ViewerAttach {
                id,
                ip: "10.0.0.1".into(),
                pubkey: Some("ssh-rsa BBBB".into()),
                access: Access::ReadWrite,
                size,
            },
            ToWorker::BackendData(vec![0x92, 0, 0x91, 5]),
            ToWorker::BackendGone,
            ToWorker::ViewerInput {
                id,
                data: b"\x1b[A".to_vec(),
            },
            ToWorker::ViewerResize { id, size },
            ToWorker::ViewerDetach(id),
            ToWorker::ReconnectResult {
                tokens: None,
                reconnection_data: String::new(),
            },
            ToWorker::ReconnectResult {
                tokens: Some(tokens.clone()),
                reconnection_data: "p|s".into(),
            },
            ToWorker::HostAdopted {
                epoch: 3,
                peer_ip: "198.51.100.2".into(),
                client_version: "2.4.0".into(),
            },
        ] {
            roundtrip_worker(msg);
        }
        for msg in [
            ToGateway::Ready {
                sandbox: "userns ok".into(),
                level: 2,
            },
            ToGateway::ToHost {
                epoch: 1,
                data: vec![1, 2, 3],
            },
            ToGateway::CloseHost { epoch: 1 },
            ToGateway::ToViewer {
                id,
                data: vec![0; 300],
            },
            ToGateway::CloseViewer(id),
            ToGateway::Register(tokens.clone()),
            ToGateway::Unregister(tokens.clone()),
            ToGateway::AuthorizedKeys {
                enabled: true,
                keys: vec!["ssh-ed25519 AAAA".into(), "ssh-rsa BBBB".into()],
            },
            ToGateway::Reconnect {
                data: "abc|def".into(),
                rest: vec![0x91, 0x0c],
                client_version: "2.4.0".into(),
            },
            ToGateway::ToBackend(vec![0x92, 1, 0x91, 9]),
            ToGateway::CloseBackend,
        ] {
            roundtrip_gateway(msg);
        }
    }

    #[test]
    fn frames_arrive_in_arbitrary_pieces() {
        let a = ToWorker::HostData(vec![1; 1000]).encode();
        let b = ToWorker::HostGone.encode();
        let mut all = a.clone();
        all.extend_from_slice(&b);
        let mut framer = Framer::new();
        for chunk in all.chunks(7) {
            framer.feed(chunk);
        }
        let first = framer.next_frame().unwrap().unwrap();
        assert_eq!(
            ToWorker::decode(&first).unwrap(),
            ToWorker::HostData(vec![1; 1000])
        );
        let second = framer.next_frame().unwrap().unwrap();
        assert_eq!(ToWorker::decode(&second).unwrap(), ToWorker::HostGone);
        assert_eq!(framer.next_frame().unwrap(), None);
    }

    #[test]
    fn truncated_frames_wait_for_more() {
        let bytes = ToWorker::HostData(vec![9; 50]).encode();
        let mut framer = Framer::new();
        framer.feed(&bytes[..3]);
        assert_eq!(framer.next_frame().unwrap(), None);
        framer.feed(&bytes[3..bytes.len() - 1]);
        assert_eq!(framer.next_frame().unwrap(), None);
        framer.feed(&bytes[bytes.len() - 1..]);
        assert!(framer.next_frame().unwrap().is_some());
    }

    #[test]
    fn oversize_frames_are_refused_before_allocation() {
        let mut framer = Framer::new();
        framer.feed(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert_eq!(
            framer.next_frame(),
            Err(Error::FrameTooLarge(MAX_FRAME + 1))
        );
        let mut framer = Framer::new();
        framer.feed(&u32::MAX.to_be_bytes());
        assert!(matches!(framer.next_frame(), Err(Error::FrameTooLarge(_))));
    }

    #[test]
    fn malformed_payloads_are_errors() {
        assert!(matches!(ToWorker::decode(&[]), Err(Error::Malformed(_))));
        // A truncated string header.
        assert!(matches!(
            ToWorker::decode(&[0x91, 0xd9]),
            Err(Error::Malformed(_))
        ));
        // Not an array.
        assert!(matches!(
            ToWorker::decode(&[0x01]),
            Err(Error::Malformed(_))
        ));
        // Unknown tag.
        assert_eq!(ToWorker::decode(&[0x91, 0x63]), Err(Error::UnknownTag(99)));
        // Right tag, wrong field type.
        assert!(matches!(
            ToWorker::decode(&[0x92, 0x02, 0x05]),
            Err(Error::Malformed(_))
        ));
        // Trailing bytes after the array.
        assert!(matches!(
            ToWorker::decode(&[0x91, 0x03, 0x00]),
            Err(Error::Malformed(_))
        ));
        // A map is not a type the codec accepts.
        assert!(matches!(ToGateway::decode(&[0x80]), Err(Error::Msgpack(_))));
        // Tokens must look like tokens.
        let mut enc = Encoder::new();
        enc.array(3).int(REGISTER).str("x").str("y");
        assert!(matches!(
            ToGateway::decode(&enc.take()),
            Err(Error::Malformed(_))
        ));
    }
}
