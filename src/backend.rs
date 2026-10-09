//! The control protocol (version 2) between a session and the
//! tmate-websocket backend (`-w`/`-z`), as `tmate-websocket.c` and
//! `tmate-protocol.h` define it. One TCP connection per session carries
//! msgpack arrays `[type, fields…]` in both directions, with no framing
//! beyond msgpack itself.
//!
//! Server to backend (`tmate_control_out_msg_types`):
//!
//! ```text
//! [CTL_HEADER, 2, ip, pubkey|nil, token, token_ro, ssh_cmd_fmt, client_version, protocol]
//! [CTL_DEAMON_OUT_MSG, <a host message, verbatim>]
//! [CTL_SNAPSHOT, [[pane_id, [cx, cy], mode, [[line_utf8, [cell, …]], …]], …]]
//! [CTL_CLIENT_JOIN, client_id, ip, pubkey|nil, readonly]
//! [CTL_CLIENT_LEFT, client_id]
//! [CTL_EXEC, username, ip, pubkey|nil, command]
//! [CTL_LATENCY, client_id, latency_ms]   (never sent by the old server)
//! ```
//!
//! Backend to server (`tmate_control_in_msg_types`):
//!
//! ```text
//! [CTL_DEAMON_FWD_MSG, <a message for the host, forwarded verbatim>]
//! [CTL_REQUEST_SNAPSHOT, max_history_lines]
//! [CTL_PANE_KEYS, pane_id, keys]
//! [CTL_RESIZE, sx, sy]                    (-1: no web clients)
//! [CTL_EXEC_RESPONSE, exit_code, message]
//! [CTL_RENAME_SESSION, token, token_ro]
//! ```

use crate::msgpack::{Encoder, Value};
use crate::session::{self, Tokens};

pub const CONTROL_PROTOCOL_VERSION: i64 = 2;

/// `TMATE_DEFAULT_WEBSOCKET_PORT`.
pub const DEFAULT_PORT: u16 = 4002;

const CTL_HEADER: i64 = 0;
const CTL_DEAMON_OUT_MSG: i64 = 1;
const CTL_SNAPSHOT: i64 = 2;
const CTL_CLIENT_JOIN: i64 = 3;
const CTL_CLIENT_LEFT: i64 = 4;
const CTL_EXEC: i64 = 5;

const CTL_DEAMON_FWD_MSG: i64 = 0;
const CTL_REQUEST_SNAPSHOT: i64 = 1;
const CTL_PANE_KEYS: i64 = 2;
const CTL_RESIZE: i64 = 3;
const CTL_EXEC_RESPONSE: i64 = 4;
const CTL_RENAME_SESSION: i64 = 5;

/// Where the backend listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// What the backend sends a session.
#[derive(Debug, Clone, PartialEq)]
pub enum CtlIn {
    /// A message for the host, sent to it as is.
    FwdMsg(Value),
    RequestSnapshot {
        max_history_lines: i64,
    },
    /// Each byte is one key for `pane` (-1: the active pane), as
    /// `ctl_pane_keys` sent them.
    PaneKeys {
        pane: i64,
        keys: Vec<u8>,
    },
    /// The smallest web client, or -1 -1 for none.
    Resize {
        sx: i64,
        sy: i64,
    },
    ExecResponse {
        exit_code: i64,
        message: String,
    },
    RenameSession(Tokens),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

fn int(v: Option<&Value>, what: &str) -> Result<i64, ParseError> {
    v.and_then(Value::as_int)
        .ok_or_else(|| ParseError(format!("{what}: expected integer")))
}

fn string(v: Option<&Value>, what: &str) -> Result<String, ParseError> {
    v.and_then(Value::as_bytes)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .ok_or_else(|| ParseError(format!("{what}: expected string")))
}

impl CtlIn {
    pub fn parse(v: &Value) -> Result<CtlIn, ParseError> {
        let items = v
            .as_array()
            .ok_or_else(|| ParseError("backend message: expected array".into()))?;
        let kind = int(items.first(), "backend message")?;
        let f = |i: usize| items.get(i);
        Ok(match kind {
            CTL_DEAMON_FWD_MSG => CtlIn::FwdMsg(
                f(1).cloned()
                    .ok_or_else(|| ParseError("fwd_msg: missing message".into()))?,
            ),
            CTL_REQUEST_SNAPSHOT => CtlIn::RequestSnapshot {
                max_history_lines: int(f(1), "request_snapshot")?,
            },
            CTL_PANE_KEYS => CtlIn::PaneKeys {
                pane: int(f(1), "pane_keys")?,
                keys: f(2)
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| ParseError("pane_keys: expected string".into()))?,
            },
            CTL_RESIZE => CtlIn::Resize {
                sx: int(f(1), "resize")?,
                sy: int(f(2), "resize")?,
            },
            CTL_EXEC_RESPONSE => CtlIn::ExecResponse {
                exit_code: int(f(1), "exec_response")?,
                message: string(f(2), "exec_response")?,
            },
            CTL_RENAME_SESSION => {
                let rw = string(f(1), "rename_session")?;
                let ro = string(f(2), "rename_session")?;
                if !session::is_acceptable_token(&rw) || !session::is_acceptable_token(&ro) {
                    return Err(ParseError("rename_session: invalid token".into()));
                }
                CtlIn::RenameSession(Tokens { rw, ro })
            }
            other => return Err(ParseError(format!("unknown backend message type {other}"))),
        })
    }
}

fn string_or_nil(enc: &mut Encoder, s: Option<&str>) {
    match s {
        Some(s) => enc.str(s),
        None => enc.nil(),
    };
}

/// What the session tells the backend about its host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'a> {
    pub ip: &'a str,
    pub pubkey: Option<&'a str>,
    pub tokens: &'a Tokens,
    /// `ssh -p<port> %s@<host>`.
    pub ssh_cmd_fmt: &'a str,
    pub client_version: &'a str,
    pub client_protocol: i64,
}

pub fn encode_header(enc: &mut Encoder, h: &Header<'_>) {
    enc.array(9)
        .int(CTL_HEADER)
        .int(CONTROL_PROTOCOL_VERSION)
        .str(h.ip);
    string_or_nil(enc, h.pubkey);
    enc.str(&h.tokens.rw)
        .str(&h.tokens.ro)
        .str(h.ssh_cmd_fmt)
        .str(h.client_version)
        .int(h.client_protocol);
}

/// A host message, already encoded, wrapped for the backend.
pub fn encode_daemon_out_msg(enc: &mut Encoder, raw: &[u8]) {
    enc.array(2).int(CTL_DEAMON_OUT_MSG);
    enc.buf.extend_from_slice(raw);
}

pub fn encode_client_join(
    enc: &mut Encoder,
    client_id: i64,
    ip: &str,
    pubkey: Option<&str>,
    readonly: bool,
) {
    enc.array(5).int(CTL_CLIENT_JOIN).int(client_id).str(ip);
    string_or_nil(enc, pubkey);
    enc.bool(readonly);
}

pub fn encode_client_left(enc: &mut Encoder, client_id: i64) {
    enc.array(2).int(CTL_CLIENT_LEFT).int(client_id);
}

pub fn encode_exec(
    enc: &mut Encoder,
    username: &str,
    ip: &str,
    pubkey: Option<&str>,
    command: &str,
) {
    enc.array(5).int(CTL_EXEC).str(username).str(ip);
    string_or_nil(enc, pubkey);
    enc.str(command);
}

/// One line of a pane snapshot: its text and one packed cell word per
/// written cell (`snapshot::encode_cell`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotLine {
    pub text: String,
    pub cells: Vec<u32>,
}

/// One pane as `do_snapshot` packed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneSnapshot {
    pub id: i64,
    pub cx: i64,
    pub cy: i64,
    pub mode: u32,
    pub lines: Vec<SnapshotLine>,
}

pub fn encode_snapshot(enc: &mut Encoder, panes: &[PaneSnapshot]) {
    enc.array(2).int(CTL_SNAPSHOT).array(panes.len());
    for p in panes {
        enc.array(4).int(p.id).array(2).int(p.cx).int(p.cy);
        enc.uint(u64::from(p.mode)).array(p.lines.len());
        for line in &p.lines {
            enc.array(2).str(&line.text).array(line.cells.len());
            for cell in &line.cells {
                enc.uint(u64::from(*cell));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgpack::Decoder;

    fn decode(enc: &Encoder) -> Value {
        let mut d = Decoder::new();
        d.feed(&enc.buf);
        let v = d.next_value().unwrap().unwrap();
        assert!(d.take_pending().is_empty());
        v
    }

    fn s(text: &str) -> Value {
        Value::Bytes(text.as_bytes().to_vec())
    }

    #[test]
    fn header_fields_in_order() {
        let tokens = Tokens {
            rw: "abc".into(),
            ro: "ro-abc".into(),
        };
        let mut e = Encoder::new();
        encode_header(
            &mut e,
            &Header {
                ip: "203.0.113.5",
                pubkey: None,
                tokens: &tokens,
                ssh_cmd_fmt: "ssh -p2200 %s@h",
                client_version: "2.4.0",
                client_protocol: 6,
            },
        );
        assert_eq!(
            decode(&e),
            Value::Array(vec![
                Value::Int(0),
                Value::Int(2),
                s("203.0.113.5"),
                Value::Nil,
                s("abc"),
                s("ro-abc"),
                s("ssh -p2200 %s@h"),
                s("2.4.0"),
                Value::Int(6),
            ])
        );
        let mut e = Encoder::new();
        encode_header(
            &mut e,
            &Header {
                ip: "::1",
                pubkey: Some("ssh-ed25519 AAAA"),
                tokens: &tokens,
                ssh_cmd_fmt: "ssh %s@h",
                client_version: "2.4.0",
                client_protocol: 6,
            },
        );
        assert_eq!(decode(&e).as_array().unwrap()[3], s("ssh-ed25519 AAAA"));
    }

    #[test]
    fn daemon_out_msg_wraps_raw_bytes() {
        let mut host = Encoder::new();
        host.array(3).int(2).int(0).bin(b"hi");
        let raw = host.take();
        let mut e = Encoder::new();
        encode_daemon_out_msg(&mut e, &raw);
        assert_eq!(
            decode(&e),
            Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![Value::Int(2), Value::Int(0), s("hi")])
            ])
        );
    }

    #[test]
    fn presence_and_exec() {
        let mut e = Encoder::new();
        encode_client_join(&mut e, 7, "10.0.0.1", None, true);
        assert_eq!(
            decode(&e),
            Value::Array(vec![
                Value::Int(3),
                Value::Int(7),
                s("10.0.0.1"),
                Value::Nil,
                Value::Bool(true)
            ])
        );
        let mut e = Encoder::new();
        encode_client_left(&mut e, 7);
        assert_eq!(decode(&e), Value::Array(vec![Value::Int(4), Value::Int(7)]));
        let mut e = Encoder::new();
        encode_exec(
            &mut e,
            "tok",
            "10.0.0.2",
            Some("ssh-rsa B"),
            "explain-session-not-found",
        );
        assert_eq!(
            decode(&e),
            Value::Array(vec![
                Value::Int(5),
                s("tok"),
                s("10.0.0.2"),
                s("ssh-rsa B"),
                s("explain-session-not-found")
            ])
        );
    }

    #[test]
    fn snapshot_shape() {
        let mut e = Encoder::new();
        encode_snapshot(
            &mut e,
            &[PaneSnapshot {
                id: 3,
                cx: 1,
                cy: 0,
                mode: 0x11,
                lines: vec![
                    SnapshotLine {
                        text: "ab".into(),
                        cells: vec![0x0808, 0x0101_0808],
                    },
                    SnapshotLine {
                        text: String::new(),
                        cells: vec![],
                    },
                ],
            }],
        );
        assert_eq!(
            decode(&e),
            Value::Array(vec![
                Value::Int(2),
                Value::Array(vec![Value::Array(vec![
                    Value::Int(3),
                    Value::Array(vec![Value::Int(1), Value::Int(0)]),
                    Value::Int(0x11),
                    Value::Array(vec![
                        Value::Array(vec![
                            s("ab"),
                            Value::Array(vec![Value::Int(0x0808), Value::Int(0x0101_0808)])
                        ]),
                        Value::Array(vec![s(""), Value::Array(vec![])]),
                    ]),
                ])])
            ])
        );
    }

    #[test]
    fn parses_every_incoming_message() {
        let mut e = Encoder::new();
        e.array(2).int(0).array(2).int(0).str("notice");
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::FwdMsg(Value::Array(vec![Value::Int(0), s("notice")]))
        );
        let mut e = Encoder::new();
        e.array(2).int(1).int(300);
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::RequestSnapshot {
                max_history_lines: 300
            }
        );
        let mut e = Encoder::new();
        e.array(3).int(2).int(-1).str("ls\r");
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::PaneKeys {
                pane: -1,
                keys: b"ls\r".to_vec()
            }
        );
        let mut e = Encoder::new();
        e.array(3).int(3).int(-1).int(-1);
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::Resize { sx: -1, sy: -1 }
        );
        let mut e = Encoder::new();
        e.array(3).int(4).int(1).str("Invalid command\r\n");
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::ExecResponse {
                exit_code: 1,
                message: "Invalid command\r\n".into()
            }
        );
        let mut e = Encoder::new();
        e.array(3).int(5).str("acme/demo").str("ro-acme/demo");
        assert_eq!(
            CtlIn::parse(&decode(&e)).unwrap(),
            CtlIn::RenameSession(Tokens {
                rw: "acme/demo".into(),
                ro: "ro-acme/demo".into()
            })
        );
    }

    #[test]
    fn rejects_malformed_messages() {
        assert!(CtlIn::parse(&Value::Int(1)).is_err());
        assert!(CtlIn::parse(&Value::Array(vec![Value::Int(99)])).is_err());
        assert!(CtlIn::parse(&Value::Array(vec![Value::Int(0)])).is_err());
        assert!(CtlIn::parse(&Value::Array(vec![Value::Int(3), Value::Int(1)])).is_err());
        assert!(
            CtlIn::parse(&Value::Array(vec![
                Value::Int(5),
                s("bad token!"),
                s("ro-x")
            ]))
            .is_err()
        );
        assert!(
            CtlIn::parse(&Value::Array(vec![
                Value::Int(2),
                Value::Int(0),
                Value::Int(1)
            ]))
            .is_err()
        );
    }
}
