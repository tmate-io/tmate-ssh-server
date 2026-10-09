//! tmate daemon protocol, version 6 (tmate 2.4.0).
//!
//! `HostMsg` is what the host's tmate client sends; `encode_*` builds what
//! the server sends back. Parsing turns untyped msgpack into typed messages
//! and rejects anything malformed; range checks that depend on session state
//! (pane counts, sizes) happen in the worker.

use crate::msgpack::{Encoder, Value};

pub const PROTOCOL_VERSION: i64 = 6;

// Host -> server message types (tmate_daemon_out_msg_types).
const OUT_HEADER: i64 = 0;
const OUT_SYNC_LAYOUT: i64 = 1;
const OUT_PTY_DATA: i64 = 2;
const OUT_EXEC_CMD_STR: i64 = 3;
const OUT_FAILED_CMD: i64 = 4;
const OUT_STATUS: i64 = 5;
const OUT_SYNC_COPY_MODE: i64 = 6;
const OUT_WRITE_COPY_MODE: i64 = 7;
const OUT_FIN: i64 = 8;
const OUT_READY: i64 = 9;
const OUT_RECONNECT: i64 = 10;
const OUT_SNAPSHOT: i64 = 11;
const OUT_EXEC_CMD: i64 = 12;
const OUT_UNAME: i64 = 13;

// Server -> host message types (tmate_daemon_in_msg_types).
const IN_NOTIFY: i64 = 0;
const IN_RESIZE: i64 = 2;
const IN_SET_ENV: i64 = 4;
const IN_READY: i64 = 5;
const IN_PANE_KEY: i64 = 6;
const IN_EXEC_CMD: i64 = 7;

#[derive(Debug, Clone, PartialEq)]
pub struct PaneGeom {
    pub id: i64,
    pub sx: i64,
    pub sy: i64,
    pub xoff: i64,
    pub yoff: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WindowLayout {
    pub idx: i64,
    pub name: String,
    pub panes: Vec<PaneGeom>,
    pub active_pane: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    pub sx: i64,
    pub sy: i64,
    pub windows: Vec<WindowLayout>,
    pub active_window: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    pub x: i64,
    /// Line counted from the bottom of the history, as the client packs it.
    pub y_from_bottom: i64,
    pub rect: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CopyModeInput {
    pub kind: i64,
    pub prompt: String,
    pub input: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CopyMode {
    pub backing: bool,
    pub oy: i64,
    pub cx: i64,
    pub cy: i64,
    pub selection: Option<Selection>,
    pub input: Option<CopyModeInput>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotLine {
    pub text: String,
    pub cells: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotGrid {
    pub cx: i64,
    pub cy: i64,
    pub lines: Vec<SnapshotLine>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaneSnapshot {
    pub id: i64,
    pub mode: i64,
    pub grid: SnapshotGrid,
    pub saved: Option<SnapshotGrid>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostMsg {
    Header { protocol: i64, version: String },
    SyncLayout(Layout),
    PtyData { pane: i64, data: Vec<u8> },
    ExecCmdStr(String),
    FailedCmd { client_id: i64, cause: String },
    Status { left: String, right: String },
    SyncCopyMode { pane: i64, mode: Option<CopyMode> },
    WriteCopyMode { pane: i64, text: String },
    Fin,
    Ready,
    Reconnect(String),
    Snapshot(Vec<PaneSnapshot>),
    ExecCmd(Vec<String>),
    Uname(Vec<String>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ParseError(msg.into()))
}

/// Sequential reader over a msgpack array, mirroring tmate's `unpack_*`.
struct Args<'a> {
    items: &'a [Value],
    what: &'static str,
}

impl<'a> Args<'a> {
    fn new(v: &'a Value, what: &'static str) -> Result<Self> {
        match v.as_array() {
            Some(items) => Ok(Args { items, what }),
            None => err(format!("{what}: expected array")),
        }
    }

    fn remaining(&self) -> usize {
        self.items.len()
    }

    fn next(&mut self) -> Result<&'a Value> {
        match self.items.split_first() {
            Some((head, rest)) => {
                self.items = rest;
                Ok(head)
            }
            None => err(format!("{}: missing field", self.what)),
        }
    }

    fn int(&mut self) -> Result<i64> {
        let what = self.what;
        self.next()?
            .as_int()
            .ok_or_else(|| ParseError(format!("{what}: expected integer")))
    }

    fn bool(&mut self) -> Result<bool> {
        // tmate packs booleans as integers in copy-mode state.
        match self.next()? {
            Value::Bool(b) => Ok(*b),
            Value::Int(i) => Ok(*i != 0),
            _ => err(format!("{}: expected boolean", self.what)),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let what = self.what;
        self.next()?
            .as_bytes()
            .ok_or_else(|| ParseError(format!("{what}: expected string")))
    }

    /// Strings from the host are used in notices and the status line, so
    /// invalid UTF-8 is replaced rather than rejected.
    fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    fn array(&mut self) -> Result<Args<'a>> {
        let what = self.what;
        Args::new(self.next()?, what)
    }

    fn rest_strings(&mut self) -> Result<Vec<String>> {
        let mut out = Vec::with_capacity(self.remaining());
        while self.remaining() > 0 {
            out.push(self.string()?);
        }
        Ok(out)
    }
}

/// Upper bounds on per-message counts, checked before anything is stored.
pub const MAX_WINDOWS: usize = 100;
pub const MAX_PANES: usize = 1000;
pub const MAX_SNAPSHOT_LINES: usize = 10_000;
pub const MAX_LINE_CELLS: usize = 4096;

fn parse_layout(uk: &mut Args<'_>) -> Result<Layout> {
    let sx = uk.int()?;
    let sy = uk.int()?;
    let mut windows_uk = uk.array()?;
    if windows_uk.remaining() > MAX_WINDOWS {
        return err("layout: too many windows");
    }
    let mut windows = Vec::with_capacity(windows_uk.remaining());
    let mut total_panes = 0usize;
    while windows_uk.remaining() > 0 {
        let mut w = windows_uk.array()?;
        let idx = w.int()?;
        let name = w.string()?;
        let mut panes_uk = w.array()?;
        total_panes += panes_uk.remaining();
        if total_panes > MAX_PANES {
            return err("layout: too many panes");
        }
        let mut panes = Vec::with_capacity(panes_uk.remaining());
        while panes_uk.remaining() > 0 {
            let mut p = panes_uk.array()?;
            panes.push(PaneGeom {
                id: p.int()?,
                sx: p.int()?,
                sy: p.int()?,
                xoff: p.int()?,
                yoff: p.int()?,
            });
        }
        let active_pane = w.int()?;
        windows.push(WindowLayout {
            idx,
            name,
            panes,
            active_pane,
        });
    }
    let active_window = uk.int()?;
    Ok(Layout {
        sx,
        sy,
        windows,
        active_window,
    })
}

fn parse_copy_mode(uk: &mut Args<'_>) -> Result<Option<CopyMode>> {
    let mut cm = uk.array()?;
    if cm.remaining() == 0 {
        return Ok(None);
    }
    let backing = cm.bool()?;
    let oy = cm.int()?;
    let cx = cm.int()?;
    let cy = cm.int()?;
    let mut sel = cm.array()?;
    let selection = if sel.remaining() == 0 {
        None
    } else {
        Some(Selection {
            x: sel.int()?,
            y_from_bottom: sel.int()?,
            rect: sel.bool()?,
        })
    };
    let mut input = cm.array()?;
    let input = if input.remaining() == 0 {
        None
    } else {
        Some(CopyModeInput {
            kind: input.int()?,
            prompt: input.string()?,
            input: input.string()?,
        })
    };
    Ok(Some(CopyMode {
        backing,
        oy,
        cx,
        cy,
        selection,
        input,
    }))
}

fn parse_snapshot_grid(uk: &mut Args<'_>) -> Result<SnapshotGrid> {
    let cx = uk.int()?;
    let cy = uk.int()?;
    let mut lines_uk = uk.array()?;
    if lines_uk.remaining() > MAX_SNAPSHOT_LINES {
        return err("snapshot: too many lines");
    }
    let mut lines = Vec::with_capacity(lines_uk.remaining());
    while lines_uk.remaining() > 0 {
        let mut line = lines_uk.array()?;
        let text = line.string()?;
        let mut cells_uk = line.array()?;
        if cells_uk.remaining() > MAX_LINE_CELLS {
            return err("snapshot: line too long");
        }
        let mut cells = Vec::with_capacity(cells_uk.remaining());
        while cells_uk.remaining() > 0 {
            let packed = cells_uk.int()?;
            cells.push(u32::try_from(packed).map_err(|_| ParseError("snapshot: bad cell".into()))?);
        }
        lines.push(SnapshotLine { text, cells });
    }
    Ok(SnapshotGrid { cx, cy, lines })
}

fn parse_snapshot(uk: &mut Args<'_>) -> Result<Vec<PaneSnapshot>> {
    let mut panes_uk = uk.array()?;
    if panes_uk.remaining() > MAX_PANES {
        return err("snapshot: too many panes");
    }
    let mut panes = Vec::with_capacity(panes_uk.remaining());
    while panes_uk.remaining() > 0 {
        let mut p = panes_uk.array()?;
        let id = p.int()?;
        let mode = p.int()?;
        let mut grid_uk = p.array()?;
        let grid = parse_snapshot_grid(&mut grid_uk)?;
        let saved = match p.next()? {
            Value::Nil => None,
            v => {
                let mut saved_uk = Args::new(v, "snapshot")?;
                Some(parse_snapshot_grid(&mut saved_uk)?)
            }
        };
        panes.push(PaneSnapshot {
            id,
            mode,
            grid,
            saved,
        });
    }
    Ok(panes)
}

impl HostMsg {
    pub fn parse(v: &Value) -> Result<HostMsg> {
        let mut uk = Args::new(v, "message")?;
        let kind = uk.int()?;
        Ok(match kind {
            OUT_HEADER => {
                uk.what = "header";
                let protocol = uk.int()?;
                // Older protocols have no version string; we only accept 6.
                let version = if protocol >= 3 {
                    uk.string()?
                } else {
                    String::new()
                };
                HostMsg::Header { protocol, version }
            }
            OUT_SYNC_LAYOUT => {
                uk.what = "layout";
                HostMsg::SyncLayout(parse_layout(&mut uk)?)
            }
            OUT_PTY_DATA => {
                uk.what = "pty_data";
                HostMsg::PtyData {
                    pane: uk.int()?,
                    data: uk.bytes()?.to_vec(),
                }
            }
            OUT_EXEC_CMD_STR => {
                uk.what = "exec_cmd_str";
                HostMsg::ExecCmdStr(uk.string()?)
            }
            OUT_FAILED_CMD => {
                uk.what = "failed_cmd";
                HostMsg::FailedCmd {
                    client_id: uk.int()?,
                    cause: uk.string()?,
                }
            }
            OUT_STATUS => {
                uk.what = "status";
                HostMsg::Status {
                    left: uk.string()?,
                    right: uk.string()?,
                }
            }
            OUT_SYNC_COPY_MODE => {
                uk.what = "copy_mode";
                let pane = uk.int()?;
                let mode = parse_copy_mode(&mut uk)?;
                HostMsg::SyncCopyMode { pane, mode }
            }
            OUT_WRITE_COPY_MODE => {
                uk.what = "write_copy_mode";
                HostMsg::WriteCopyMode {
                    pane: uk.int()?,
                    text: uk.string()?,
                }
            }
            OUT_FIN => HostMsg::Fin,
            OUT_READY => HostMsg::Ready,
            OUT_RECONNECT => {
                uk.what = "reconnect";
                HostMsg::Reconnect(uk.string()?)
            }
            OUT_SNAPSHOT => {
                uk.what = "snapshot";
                HostMsg::Snapshot(parse_snapshot(&mut uk)?)
            }
            OUT_EXEC_CMD => {
                uk.what = "exec_cmd";
                let args = uk.rest_strings()?;
                if args.is_empty() {
                    return err("exec_cmd: no command");
                }
                HostMsg::ExecCmd(args)
            }
            OUT_UNAME => {
                uk.what = "uname";
                HostMsg::Uname(uk.rest_strings()?)
            }
            other => return err(format!("unknown message type {other}")),
        })
    }
}

/// Builders for server -> host messages. Each appends one message to `enc`.
pub fn encode_notify(enc: &mut Encoder, msg: &str) {
    enc.array(2).int(IN_NOTIFY).str(msg);
}

/// `sx == -1` tells the host no viewer is attached.
pub fn encode_resize(enc: &mut Encoder, sx: i64, sy: i64) {
    enc.array(3).int(IN_RESIZE).int(sx).int(sy);
}

pub fn encode_set_env(enc: &mut Encoder, name: &str, value: &str) {
    enc.array(3).int(IN_SET_ENV).str(name).str(value);
}

pub fn encode_ready(enc: &mut Encoder) {
    enc.array(1).int(IN_READY);
}

/// `pane == -1` means the host's active pane.
pub fn encode_pane_key(enc: &mut Encoder, pane: i64, key: u64) {
    enc.array(3).int(IN_PANE_KEY).int(pane).uint(key);
}

pub fn encode_exec_cmd(enc: &mut Encoder, client_id: i64, args: &[&str]) {
    enc.array(2 + args.len()).int(IN_EXEC_CMD).int(client_id);
    for a in args {
        enc.str(a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgpack::Decoder;

    fn parse(enc: &Encoder) -> HostMsg {
        let mut d = Decoder::new();
        d.feed(&enc.buf);
        HostMsg::parse(&d.next_value().unwrap().unwrap()).unwrap()
    }

    #[test]
    fn header() {
        let mut e = Encoder::new();
        e.array(3).int(OUT_HEADER).int(6).str("2.4.0");
        assert_eq!(
            parse(&e),
            HostMsg::Header {
                protocol: 6,
                version: "2.4.0".into()
            }
        );
    }

    #[test]
    fn layout() {
        let mut e = Encoder::new();
        // [SYNC_LAYOUT, sx, sy, [[idx, name, [[id, sx, sy, xoff, yoff]], active_pane]], active_win]
        e.array(5).int(OUT_SYNC_LAYOUT).int(80).int(24);
        e.array(1)
            .array(4)
            .int(0)
            .str("bash")
            .array(1)
            .array(5)
            .int(0)
            .int(80)
            .int(23)
            .int(0)
            .int(0);
        e.int(0);
        e.int(0);
        let HostMsg::SyncLayout(l) = parse(&e) else {
            panic!()
        };
        assert_eq!(l.sx, 80);
        assert_eq!(l.windows.len(), 1);
        assert_eq!(l.windows[0].name, "bash");
        assert_eq!(l.windows[0].panes[0].sy, 23);
        assert_eq!(l.active_window, 0);
    }

    #[test]
    fn copy_mode_empty_and_full() {
        let mut e = Encoder::new();
        e.array(3).int(OUT_SYNC_COPY_MODE).int(0).array(0);
        assert_eq!(
            parse(&e),
            HostMsg::SyncCopyMode {
                pane: 0,
                mode: None
            }
        );

        let mut e = Encoder::new();
        e.array(3).int(OUT_SYNC_COPY_MODE).int(0);
        e.array(6)
            .int(1)
            .int(5)
            .int(3)
            .int(7)
            .array(3)
            .int(1)
            .int(2)
            .int(0)
            .array(0);
        let HostMsg::SyncCopyMode { mode: Some(m), .. } = parse(&e) else {
            panic!()
        };
        assert!(m.backing);
        assert_eq!(m.oy, 5);
        assert_eq!(m.selection.unwrap().y_from_bottom, 2);
        assert!(m.input.is_none());
    }

    #[test]
    fn snapshot() {
        let mut e = Encoder::new();
        e.array(2).int(OUT_SNAPSHOT).array(1);
        e.array(4).int(0).int(1);
        e.array(3)
            .int(2)
            .int(0)
            .array(1)
            .array(2)
            .str("hi")
            .array(2)
            .uint(0x0000_0708)
            .uint(8);
        e.nil();
        let HostMsg::Snapshot(p) = parse(&e) else {
            panic!()
        };
        assert_eq!(p[0].grid.lines[0].text, "hi");
        assert_eq!(p[0].grid.lines[0].cells, vec![0x708, 8]);
        assert!(p[0].saved.is_none());
    }

    #[test]
    fn exec_cmd_and_bad_input() {
        let mut e = Encoder::new();
        e.array(4)
            .int(OUT_EXEC_CMD)
            .str("set-option")
            .str("tmate-set")
            .str("authorized_keys=ssh-ed25519 AAAA");
        assert_eq!(
            parse(&e),
            HostMsg::ExecCmd(vec![
                "set-option".into(),
                "tmate-set".into(),
                "authorized_keys=ssh-ed25519 AAAA".into()
            ])
        );

        assert!(HostMsg::parse(&Value::Int(3)).is_err());
        assert!(HostMsg::parse(&Value::Array(vec![Value::Int(99)])).is_err());
        assert!(HostMsg::parse(&Value::Array(vec![Value::Int(OUT_PTY_DATA)])).is_err());
    }

    #[test]
    fn encoders() {
        let mut e = Encoder::new();
        encode_set_env(&mut e, "tmate_ssh", "ssh x@h");
        encode_ready(&mut e);
        encode_pane_key(&mut e, -1, 0x100000000000);
        let mut d = Decoder::new();
        d.feed(&e.buf);
        assert_eq!(
            d.next_value().unwrap().unwrap(),
            Value::Array(vec![
                Value::Int(IN_SET_ENV),
                Value::Bytes(b"tmate_ssh".to_vec()),
                Value::Bytes(b"ssh x@h".to_vec())
            ])
        );
        assert_eq!(
            d.next_value().unwrap().unwrap(),
            Value::Array(vec![Value::Int(IN_READY)])
        );
        assert_eq!(
            d.next_value().unwrap().unwrap(),
            Value::Array(vec![
                Value::Int(IN_PANE_KEY),
                Value::Int(-1),
                Value::Int(0x100000000000)
            ])
        );
    }
}
