//! Per-session hub: the host's pane contents and the viewers looking at them.
//!
//! `State` is pure: it is driven by host messages and viewer events, and
//! every method returns the bytes that must go out as a result, addressed by
//! peer, without doing any I/O. `Hub` wraps a `State` in a mutex and hands
//! the output to each peer's writer task after releasing the lock, so no SSH
//! task ever waits on another one while holding the hub. Delayed work
//! (status messages and `display-panes` expiring) is requested by the state
//! as `Timer`s and scheduled by the hub.
//!
//! Each viewer sees the active window laid out for its own terminal: all
//! panes with borders, the status line, and its own overlays (prompt,
//! message, pane numbers). Frames are diffs against what the viewer's
//! terminal shows.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::ChannelId;
use russh::keys::PublicKey;
use russh::server::Handle;
use tokio::sync::{Notify, mpsc};
use tracing::debug;

use crate::backend;
use crate::bindings::{Action, KeyState, KeyTables, Options};
use crate::cmdline::{self, Args};
use crate::copymode::CopyState;
use crate::cut::Cut;
use crate::grid;
use crate::keys::KeyParser;
use crate::layout::{self, PaneRect, Window};
use crate::msgpack::Encoder;
use crate::prompt::{Outcome, Prompt};
use crate::proto::{self, HostMsg, Layout, MAX_PANES};
use crate::render::{self, Canvas, Cell, Size, StatusLine, WindowEntry};
use crate::session::Access;
use crate::snapshot;

/// Largest pane kept per dimension. The host decides pane sizes, so a
/// hostile host could otherwise make us allocate huge grids; layouts beyond
/// this are clamped rather than refused because only its own display suffers.
pub const MAX_PANE_DIM: u16 = 500;

/// Viewer terminals larger than this are treated as this size, which keeps
/// the size reported to the host within `MAX_PANE_DIM` too.
pub const MAX_VIEWER_DIM: u16 = MAX_PANE_DIM;

/// History kept per pane (`TMATE_HLIMIT`).
pub const SCROLLBACK: usize = 2000;

/// Delay before a lone ESC from a viewer is sent as a plain Escape key.
pub const ESC_FLUSH_DELAY: Duration = Duration::from_millis(50);

pub const SESSION_ENDED: &[u8] = b"\r\n[tmate] session ended\r\n";

/// What a host without `-a` keys is told when the server runs with
/// `--authorized-keys-only`; wording from the old `tmate-daemon-decoder.c`.
pub const AUTHORIZED_KEYS_ONLY_ERROR_MSG: [&str; 3] = [
    "Server requires authorized_keys but none are given.",
    "Use '-a FILENAME' to specify an authorized_keys file.",
    "Press <Ctrl-c><Ctrl-d> to exit.",
];

/// Status message viewers get when their host reconnected.
pub const RECONNECTED_MSG: &str = "Reconnected";

/// `handle_session_name_options`: what a host asking for a named session
/// is told when there is no backend to name it.
pub const NAMED_SESSIONS_UNSUPPORTED_MSG: &str =
    "Named sessions are not supported (no websocket server)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Data(Bytes),
    /// EOF then close the channel; the peer's writer stops afterwards.
    Close,
}

/// One thing to send to one peer, in the order produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing<P> {
    pub to: P,
    pub payload: Payload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ViewerId(u64);

impl ViewerId {
    /// The `client_id` the host sees in `EXEC_CMD`/`FAILED_CMD`.
    fn client_id(self) -> i64 {
        self.0 as i64
    }

    pub fn from_raw(n: u64) -> ViewerId {
        ViewerId(n)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Delayed work the state asked for. `generation` lets an expired timer
/// recognise that what it was meant to clear has been replaced since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timer {
    Message {
        viewer: ViewerId,
        generation: u64,
        after: Duration,
    },
    Identify {
        viewer: ViewerId,
        generation: u64,
        after: Duration,
    },
}

struct Pane {
    parser: vt100::Parser,
    copy: Option<CopyState>,
}

impl Pane {
    fn new(rows: u16, cols: u16) -> Pane {
        Pane {
            parser: vt100::Parser::new(rows, cols, SCROLLBACK),
            copy: None,
        }
    }

    fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// tmux's resize: lines move between the screen and the history. On
    /// the alternate screen the application redraws anyway, so the grid
    /// is simply cut.
    fn resize(&mut self, rows: u16, cols: u16) {
        if self.parser.screen().alternate_screen() {
            self.parser.screen_mut().set_size(rows, cols);
        } else {
            self.parser = grid::resize(&mut self.parser, rows, cols, SCROLLBACK);
        }
        if let Some(copy) = &mut self.copy {
            copy.resize(rows, cols);
        }
    }

    /// Feeds pane output with tmux's history semantics the parser lacks:
    /// `CSI 3 J` empties the history, and `CSI 2 J` or a `CSI J` with the
    /// cursor on the top row (what `clear` sends under TERM=screen)
    /// scroll the used screen lines into it. A sequence split across two
    /// chunks is missed.
    fn process(&mut self, mut data: &[u8]) {
        while let Some((pos, len, kind)) = grid::find_erase(data) {
            self.parser.process(&data[..pos]);
            let seq = &data[pos..pos + len];
            data = &data[pos + len..];
            if self.parser.screen().alternate_screen() {
                self.parser.process(seq);
                continue;
            }
            match kind {
                grid::Erase::History => {
                    self.parser = grid::clear_history(&mut self.parser, SCROLLBACK);
                    continue;
                }
                grid::Erase::Screen => {
                    self.parser = grid::clear_screen_into_history(&mut self.parser, SCROLLBACK);
                }
                grid::Erase::ToEnd => {
                    if self.parser.screen().cursor_position().0 == 0 {
                        self.parser = grid::clear_screen_into_history(&mut self.parser, SCROLLBACK);
                    }
                }
            }
            self.parser.process(seq);
        }
        self.parser.process(data);
    }

    /// The pane's cells and cursor as currently shown: copy mode if the
    /// host is in it, the live screen otherwise.
    fn draw(&mut self) -> (Vec<Vec<Cell>>, Option<(u16, u16)>) {
        if let Some(copy) = &mut self.copy {
            let (cells, cursor) = copy.draw(&mut self.parser);
            return (cells, Some(cursor));
        }
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let cells = (0..rows)
            .map(|r| {
                (0..cols)
                    .map(|c| screen.cell(r, c).map(Cell::from_vt).unwrap_or_default())
                    .collect()
            })
            .collect();
        let cursor = (!screen.hide_cursor()).then(|| screen.cursor_position());
        (cells, cursor)
    }
}

struct Viewer<P> {
    peer: P,
    access: Access,
    ip: String,
    size: Size,
    /// What the viewer's terminal currently shows, so the next frame can
    /// be a diff. `None` forces a full redraw.
    last: Option<Canvas>,
    keys: KeyParser,
    /// Bumped on every input so that an ESC timer started for an earlier
    /// input does not flush bytes that arrived afterwards.
    input_gen: u64,
    keystate: KeyState,
    message: Option<String>,
    prompt: Option<Prompt>,
    /// `display-panes` is showing pane numbers.
    identify: bool,
    /// Bumped whenever a message or identify starts, so an older timer
    /// does not clear a newer one.
    timer_gen: u64,
}

/// Values for the formats tmux expands in prompts.
struct FormatValues {
    window_name: String,
    window_idx: i64,
    pane_idx: usize,
}

/// `#W`, `#I`, `#P`, `#S` and `##`; anything else stays as written.
fn expand_format(s: &str, v: &FormatValues) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '#' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('W') => out.push_str(&v.window_name),
            Some('I') => out.push_str(&v.window_idx.to_string()),
            Some('P') => out.push_str(&v.pane_idx.to_string()),
            Some('S') => out.push_str("default"),
            Some('#') => out.push('#'),
            _ => {
                out.push('#');
                continue;
            }
        }
        chars.next();
    }
    out
}

/// `*cause = toupper(*cause)` in `tmate_failed_cmd`.
fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Where a key ended up after the viewer-level checks.
enum KeyOutcome {
    Nothing,
    SelectPane(usize),
    RunString(String),
    Forward(u64),
    Run(Vec<Vec<String>>),
}

/// Session state shared by the host connection and all viewer connections.
/// Generic over the peer address type so tests can use plain values instead
/// of SSH handles.
pub struct State<P> {
    host: Option<P>,
    panes: BTreeMap<i64, Pane>,
    layout: Option<Layout>,
    /// The previously current window (`-` in the window list).
    last_window: Option<i64>,
    status_left: String,
    status_right: String,
    viewers: BTreeMap<ViewerId, Viewer<P>>,
    next_viewer: u64,
    /// `Some` once the host enabled `tmate-authorized-keys`, even if empty:
    /// an enabled empty list means nobody may join.
    authorized_keys: Option<Vec<PublicKey>>,
    keys_required: bool,
    /// Last size sent to the host, to avoid repeating it on every event.
    host_size: Option<(i64, i64)>,
    ended: bool,
    tables: KeyTables,
    options: Options,
    status_left_length: usize,
    status_right_length: usize,
    timers: Vec<Timer>,
    /// Set when the host reconnected to this session; cleared at READY.
    reconnected: bool,
    /// Bumped whenever `authorized_keys` changes, so a gateway holding a
    /// copy of the list knows when to refresh it.
    keys_generation: u64,
    /// A backend (`-w`) is attached: it produces the join/leave notices
    /// and client counts, and names sessions.
    backend: bool,
    /// The smallest web client, as the backend's `CTL_RESIZE` reported it
    /// (`websocket_sx/sy`); -1 or none means no constraint.
    backend_size: Option<(i64, i64)>,
    /// The named-session warning is given once per session.
    named_session_warned: bool,
}

impl<P: Clone> State<P> {
    pub fn new(keys_required: bool) -> Self {
        State {
            host: None,
            panes: BTreeMap::new(),
            layout: None,
            last_window: None,
            status_left: String::new(),
            status_right: String::new(),
            viewers: BTreeMap::new(),
            next_viewer: 1,
            authorized_keys: None,
            keys_required,
            host_size: None,
            ended: false,
            tables: KeyTables::tmux_defaults(),
            options: Options::default(),
            status_left_length: 10,
            status_right_length: 40,
            timers: Vec::new(),
            reconnected: false,
            keys_generation: 0,
            backend: false,
            backend_size: None,
            named_session_warned: false,
        }
    }

    /// Whether a backend handles presence notices and session names.
    pub fn set_backend(&mut self, backend: bool) {
        self.backend = backend;
    }

    pub fn host(&self) -> Option<&P> {
        self.host.as_ref()
    }

    pub fn keys_generation(&self) -> u64 {
        self.keys_generation
    }

    /// The keys the host enabled, if it enabled any.
    pub fn authorized_keys(&self) -> Option<&[PublicKey]> {
        self.authorized_keys.as_deref()
    }

    pub fn set_host(&mut self, peer: P) {
        self.host = Some(peer);
    }

    pub fn num_clients(&self) -> usize {
        self.viewers.len()
    }

    #[cfg(test)]
    pub fn pane_count(&self) -> usize {
        self.panes.len()
    }

    #[cfg(test)]
    fn pane_size(&self, id: i64) -> Option<(u16, u16)> {
        self.panes.get(&id).map(Pane::size)
    }

    /// Whether viewers must prove a listed key (`-a` on the host).
    pub fn keys_enabled(&self) -> bool {
        self.authorized_keys.is_some()
    }

    /// `--authorized-keys-only` and the host never enabled a key list.
    pub fn missing_required_keys(&self) -> bool {
        self.keys_required && self.authorized_keys.is_none()
    }

    /// Mirrors `tmate_allow_auth`: anyone without a key list, otherwise
    /// only a key whose public part is listed.
    pub fn authorize(&self, key: Option<&PublicKey>) -> bool {
        match (&self.authorized_keys, key) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(list), Some(k)) => list.iter().any(|a| a.key_data() == k.key_data()),
        }
    }

    /// Timers requested since the last call; the caller schedules them.
    pub fn take_timers(&mut self) -> Vec<Timer> {
        std::mem::take(&mut self.timers)
    }

    pub fn host_msg(&mut self, msg: &HostMsg) -> Vec<Outgoing<P>> {
        match msg {
            HostMsg::SyncLayout(layout) => {
                self.apply_layout(layout);
                self.render_all()
            }
            HostMsg::PtyData { pane, data } => {
                let Some(p) = self.panes.get_mut(pane) else {
                    return Vec::new();
                };
                p.process(data);
                if self
                    .active_window()
                    .is_some_and(|w| w.panes.iter().any(|g| g.id == *pane))
                {
                    self.render_all()
                } else {
                    Vec::new()
                }
            }
            HostMsg::Status { left, right } => {
                self.status_left = left.clone();
                self.status_right = right.clone();
                self.render_all()
            }
            HostMsg::ExecCmd(args) => self.replicated_command(args),
            HostMsg::FailedCmd { client_id, cause } => {
                let Some(id) = self
                    .viewers
                    .keys()
                    .copied()
                    .find(|id| id.client_id() == *client_id)
                else {
                    return Vec::new();
                };
                self.show_message(id, capitalise(cause));
                self.render_one(id, false)
            }
            HostMsg::SyncCopyMode { pane, mode } => {
                let Some(p) = self.panes.get_mut(pane) else {
                    return Vec::new();
                };
                match mode {
                    None => p.copy = None,
                    Some(m) => p
                        .copy
                        .get_or_insert_with(|| CopyState::new(m.backing))
                        .sync(m),
                }
                self.render_all()
            }
            HostMsg::WriteCopyMode { pane, text } => {
                let Some(p) = self.panes.get_mut(pane) else {
                    return Vec::new();
                };
                let (rows, cols) = p.size();
                p.copy
                    .get_or_insert_with(|| CopyState::new(false))
                    .add_output(text, rows, cols);
                self.render_all()
            }
            HostMsg::Snapshot(panes) => {
                for snap in panes {
                    let Some(p) = self.panes.get_mut(&snap.id) else {
                        continue;
                    };
                    let (rows, cols) = p.size();
                    p.parser = snapshot::restore(snap, rows, cols, SCROLLBACK);
                    p.copy = None;
                }
                self.render_all()
            }
            HostMsg::Header { .. }
            | HostMsg::Uname(_)
            | HostMsg::Ready
            | HostMsg::Fin
            | HostMsg::Reconnect(_)
            | HostMsg::ExecCmdStr(_) => Vec::new(),
        }
    }

    /// Takes a viewer that completed its pty and shell requests. Returns
    /// `None` when the session already ended; the output still tells the
    /// viewer so.
    #[cfg(test)]
    pub fn attach_viewer(
        &mut self,
        peer: P,
        access: Access,
        ip: &str,
        size: Size,
    ) -> (Option<ViewerId>, Vec<Outgoing<P>>) {
        let id = ViewerId(self.next_viewer);
        let out = self.attach_viewer_as(id, peer, access, ip, size);
        (self.viewers.contains_key(&id).then_some(id), out)
    }

    /// Like `attach_viewer` with an id chosen by the caller (the gateway
    /// numbers viewers so it can address them before the hub answers).
    pub fn attach_viewer_as(
        &mut self,
        id: ViewerId,
        peer: P,
        access: Access,
        ip: &str,
        size: Size,
    ) -> Vec<Outgoing<P>> {
        if self.ended || self.viewers.contains_key(&id) {
            return ended_notice(peer);
        }
        self.next_viewer = self.next_viewer.max(id.0 + 1);
        self.viewers.insert(
            id,
            Viewer {
                peer,
                access,
                ip: ip.to_string(),
                size: clamp_size(size),
                last: None,
                keys: KeyParser::default(),
                input_gen: 0,
                keystate: KeyState::default(),
                message: None,
                prompt: None,
                identify: false,
                timer_gen: 0,
            },
        );
        let mut out = self.render_one(id, true);
        out.extend(self.presence(ip, "joined"));
        out.extend(self.host_resize());
        out
    }

    pub fn detach_viewer(&mut self, id: ViewerId) -> Vec<Outgoing<P>> {
        let Some(v) = self.viewers.remove(&id) else {
            return Vec::new();
        };
        let mut out = self.presence(&v.ip, "left");
        out.extend(self.host_resize());
        out
    }

    pub fn resize_viewer(&mut self, id: ViewerId, size: Size) -> Vec<Outgoing<P>> {
        let Some(v) = self.viewers.get_mut(&id) else {
            return Vec::new();
        };
        v.size = clamp_size(size);
        v.last = None;
        let mut out = self.render_one(id, true);
        out.extend(self.host_resize());
        out
    }

    /// Feeds terminal input from a viewer. Read-only viewers are ignored.
    /// Returns the input generation when an ESC is being held, so the
    /// caller can arrange a `flush_viewer` call for it.
    pub fn viewer_input(&mut self, id: ViewerId, data: &[u8]) -> (Vec<Outgoing<P>>, Option<u64>) {
        self.viewer_input_at(id, data, Instant::now())
    }

    pub fn viewer_input_at(
        &mut self,
        id: ViewerId,
        data: &[u8],
        now: Instant,
    ) -> (Vec<Outgoing<P>>, Option<u64>) {
        let Some(v) = self.viewers.get_mut(&id) else {
            return (Vec::new(), None);
        };
        if v.access != Access::ReadWrite {
            return (Vec::new(), None);
        }
        v.input_gen += 1;
        v.keystate.begin_packet();
        let keys = v.keys.feed(data);
        let pending = v.keys.has_pending().then_some(v.input_gen);
        (self.handle_keys(id, &keys, now), pending)
    }

    /// Releases a held ESC if no input arrived since `generation`.
    pub fn flush_viewer(&mut self, id: ViewerId, generation: u64) -> Vec<Outgoing<P>> {
        let Some(v) = self.viewers.get_mut(&id) else {
            return Vec::new();
        };
        if v.input_gen != generation || v.access != Access::ReadWrite {
            return Vec::new();
        }
        let keys = v.keys.flush();
        self.handle_keys(id, &keys, Instant::now())
    }

    fn handle_keys(&mut self, id: ViewerId, keys: &[u64], now: Instant) -> Vec<Outgoing<P>> {
        let mut out = Vec::new();
        for key in keys {
            out.extend(self.handle_key(id, *key, now));
            if !self.viewers.contains_key(&id) {
                return out;
            }
        }
        if !keys.is_empty() {
            out.extend(self.render_one(id, false));
        }
        out
    }

    /// `server_client_handle_key` for one key.
    fn handle_key(&mut self, id: ViewerId, key: u64, now: Instant) -> Vec<Outgoing<P>> {
        let outcome = {
            let Some(v) = self.viewers.get_mut(&id) else {
                return Vec::new();
            };
            if v.identify && (b'0' as u64..=b'9' as u64).contains(&key) {
                v.identify = false;
                v.timer_gen += 1;
                KeyOutcome::SelectPane((key - b'0' as u64) as usize)
            } else {
                if v.message.take().is_some() || std::mem::take(&mut v.identify) {
                    v.timer_gen += 1;
                }
                if let Some(prompt) = &mut v.prompt {
                    match prompt.key(key) {
                        Outcome::Editing => KeyOutcome::Nothing,
                        Outcome::Run(cmd) => {
                            v.prompt = None;
                            KeyOutcome::RunString(cmd)
                        }
                        Outcome::Cancelled => {
                            v.prompt = None;
                            KeyOutcome::Nothing
                        }
                    }
                } else {
                    match v.keystate.handle(key, &self.tables, &self.options, now) {
                        Action::Forward(k) => KeyOutcome::Forward(k),
                        Action::Run(cmds) => KeyOutcome::Run(cmds),
                        Action::Ignore => KeyOutcome::Nothing,
                    }
                }
            }
        };
        match outcome {
            KeyOutcome::Nothing => Vec::new(),
            KeyOutcome::Forward(k) => self.send_keys(&[k]),
            KeyOutcome::Run(cmds) => self.run_commands(id, cmds),
            KeyOutcome::RunString(s) => self.run_command_string(id, &s),
            KeyOutcome::SelectPane(index) => {
                let Some(w) = self.active_window() else {
                    return Vec::new();
                };
                let Some(pane) = w.panes.get(index) else {
                    return Vec::new();
                };
                let target = format!("{}.%{}", w.idx, pane.id);
                self.exec_cmd(id, &["select-pane", "-t", &target])
            }
        }
    }

    /// A command string typed at the prompt: parse errors become status
    /// messages, as `cmd_command_prompt_callback` shows them.
    fn run_command_string(&mut self, id: ViewerId, s: &str) -> Vec<Outgoing<P>> {
        match cmdline::parse(s) {
            Ok(cmds) => self.run_commands(id, cmds),
            Err(cause) => {
                self.show_message(id, capitalise(&cause));
                Vec::new()
            }
        }
    }

    fn run_commands(&mut self, id: ViewerId, cmds: Vec<Vec<String>>) -> Vec<Outgoing<P>> {
        let mut out = Vec::new();
        for argv in cmds {
            if !self.viewers.contains_key(&id) {
                break;
            }
            out.extend(self.exec(id, &argv));
        }
        out
    }

    /// Runs one command for a viewer: the commands the old server handled
    /// itself (`local_cmds`), the prompts and `display-panes` which draw on
    /// the status line here, and everything else on the host.
    fn exec(&mut self, id: ViewerId, argv: &[String]) -> Vec<Outgoing<P>> {
        let Some((name, rest)) = argv.split_first() else {
            return Vec::new();
        };
        match name.as_str() {
            "detach-client" => {
                let Some(v) = self.viewers.get(&id) else {
                    return Vec::new();
                };
                let mut out = vec![Outgoing {
                    to: v.peer.clone(),
                    payload: Payload::Close,
                }];
                out.extend(self.detach_viewer(id));
                out
            }
            "attach-session" => Vec::new(),
            "bind-key" | "unbind-key" => {
                if let Err(cause) = self.tables.apply(argv) {
                    self.show_message(id, cause);
                }
                Vec::new()
            }
            "set-option" | "set-window-option" => {
                self.set_option(argv);
                Vec::new()
            }
            "command-prompt" => {
                let Some(args) = Args::parse("I:p:t:", rest) else {
                    self.show_message(id, "usage: command-prompt [-I inputs] [-p prompts] [-t target-client] [template]".into());
                    return Vec::new();
                };
                let values = self.format_values();
                if let Some(v) = self.viewers.get_mut(&id).filter(|v| v.prompt.is_none()) {
                    v.prompt = Some(Prompt::command_prompt(&args, &|s| {
                        expand_format(s, &values)
                    }));
                    v.message = None;
                }
                Vec::new()
            }
            "confirm-before" => {
                let prompt = Args::parse("p:t:", rest).and_then(|args| {
                    let values = self.format_values();
                    Prompt::confirm_before(&args, &|s| expand_format(s, &values))
                });
                match prompt {
                    Some(p) => {
                        if let Some(v) = self.viewers.get_mut(&id) {
                            v.prompt = Some(p);
                            v.message = None;
                        }
                    }
                    None => self.show_message(
                        id,
                        "usage: confirm-before [-p prompt] [-t target-client] command".into(),
                    ),
                }
                Vec::new()
            }
            "display-panes" => {
                let after = self.options.display_panes_time;
                if let Some(v) = self.viewers.get_mut(&id) {
                    v.identify = true;
                    v.timer_gen += 1;
                    let generation = v.timer_gen;
                    self.timers.push(Timer::Identify {
                        viewer: id,
                        generation,
                        after,
                    });
                }
                Vec::new()
            }
            _ => {
                let args: Vec<&str> = argv.iter().map(String::as_str).collect();
                self.exec_cmd(id, &args)
            }
        }
    }

    /// `EXEC_CMD client_id argv…` to the host.
    fn exec_cmd(&self, id: ViewerId, argv: &[&str]) -> Vec<Outgoing<P>> {
        let mut enc = Encoder::new();
        proto::encode_exec_cmd(&mut enc, id.client_id(), argv);
        self.to_host(enc)
    }

    /// Shows `text` on the viewer's status row until `display-time` passes
    /// or a key is pressed (`status_message_set`).
    fn show_message(&mut self, id: ViewerId, text: String) {
        let after = self.options.display_time;
        let Some(v) = self.viewers.get_mut(&id) else {
            return;
        };
        v.prompt = None;
        v.message = Some(text);
        v.timer_gen += 1;
        if !after.is_zero() {
            self.timers.push(Timer::Message {
                viewer: id,
                generation: v.timer_gen,
                after,
            });
        }
    }

    /// A scheduled timer went off.
    pub fn timer_fired(&mut self, timer: &Timer) -> Vec<Outgoing<P>> {
        let (id, generation) = match timer {
            Timer::Message {
                viewer, generation, ..
            }
            | Timer::Identify {
                viewer, generation, ..
            } => (*viewer, *generation),
        };
        let Some(v) = self.viewers.get_mut(&id) else {
            return Vec::new();
        };
        if v.timer_gen != generation {
            return Vec::new();
        }
        match timer {
            Timer::Message { .. } => v.message = None,
            Timer::Identify { .. } => v.identify = false,
        }
        self.render_one(id, false)
    }

    /// Host sent FIN or went away: viewers are told and dropped.
    pub fn end(&mut self) -> Vec<Outgoing<P>> {
        if self.ended {
            return Vec::new();
        }
        self.ended = true;
        let viewers = std::mem::take(&mut self.viewers);
        viewers
            .into_values()
            .flat_map(|v| ended_notice(v.peer))
            .collect()
    }

    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// A reconnecting host took over this session: the old host connection
    /// is closed, viewers are told, and the size is resent at READY.
    pub fn host_adopted(&mut self, peer: P) -> Vec<Outgoing<P>> {
        let mut out = Vec::new();
        if let Some(old) = self.host.replace(peer) {
            out.push(Outgoing {
                to: old,
                payload: Payload::Close,
            });
        }
        self.reconnected = true;
        let ids: Vec<ViewerId> = self.viewers.keys().copied().collect();
        for id in ids {
            self.show_message(id, RECONNECTED_MSG.into());
            out.extend(self.render_one(id, false));
        }
        out
    }

    pub fn mark_reconnected(&mut self) {
        self.reconnected = true;
    }

    /// Whether the host reconnected; true once, at READY.
    pub fn take_reconnected(&mut self) -> bool {
        std::mem::take(&mut self.reconnected)
    }

    /// The host is ready (again): a reconnected host is told the current
    /// size since its previous connection's state is gone.
    pub fn host_ready(&mut self) -> Vec<Outgoing<P>> {
        if self.host_size.take().is_none() {
            return Vec::new();
        }
        self.host_resize()
    }

    fn send_keys(&self, keys: &[u64]) -> Vec<Outgoing<P>> {
        if keys.is_empty() {
            return Vec::new();
        }
        let mut enc = Encoder::new();
        for k in keys {
            proto::encode_pane_key(&mut enc, -1, *k);
        }
        self.to_host(enc)
    }

    fn to_host(&self, mut enc: Encoder) -> Vec<Outgoing<P>> {
        match &self.host {
            Some(host) => vec![Outgoing {
                to: host.clone(),
                payload: Payload::Data(Bytes::from(enc.take())),
            }],
            None => Vec::new(),
        }
    }

    /// Join/leave notice and client count, worded as the old backend did.
    /// With a backend attached they are its job (it counts web clients
    /// too), so nothing is sent here.
    fn presence(&self, ip: &str, verb: &str) -> Vec<Outgoing<P>> {
        if self.backend {
            return Vec::new();
        }
        let n = self.viewers.len();
        let plural = if n > 1 { "s" } else { "" };
        let mut enc = Encoder::new();
        proto::encode_set_env(&mut enc, "tmate_num_clients", &n.to_string());
        proto::encode_notify(
            &mut enc,
            &format!("A mate has {verb} ({ip}) -- {n} client{plural} currently connected"),
        );
        self.to_host(enc)
    }

    /// The host's pane size follows the smallest read-write viewer, minus
    /// the status row (`resize.c`); read-only viewers never shrink it. The
    /// backend's web clients take part through `backend_resize`, each
    /// dimension on its own as `websocket_sx/sy` did.
    pub fn host_pane_size(&self) -> (i64, i64) {
        let mut sx: Option<i64> = None;
        let mut sy: Option<i64> = None;
        let mut shrink = |x: i64, y: i64| {
            if x >= 0 {
                sx = Some(sx.map_or(x, |cur| cur.min(x)));
            }
            if y >= 0 {
                sy = Some(sy.map_or(y, |cur| cur.min(y)));
            }
        };
        for v in self
            .viewers
            .values()
            .filter(|v| v.access == Access::ReadWrite)
        {
            let rows = if v.size.rows > 1 {
                i64::from(v.size.rows) - 1
            } else {
                i64::from(v.size.rows)
            };
            shrink(i64::from(v.size.cols), rows);
        }
        if let Some((x, y)) = self.backend_size {
            shrink(x, y);
        }
        match (sx, sy) {
            (Some(x), Some(y)) => (x, y),
            _ => (-1, -1),
        }
    }

    /// `CTL_RESIZE` from the backend: the smallest web client, or -1 -1
    /// for none. The host hears about it through the usual size rule.
    pub fn backend_resize(&mut self, sx: i64, sy: i64) -> Vec<Outgoing<P>> {
        let clamp = |n: i64| {
            if n < 0 {
                -1
            } else {
                n.min(i64::from(MAX_PANE_DIM))
            }
        };
        self.backend_size = Some((clamp(sx), clamp(sy)));
        self.host_resize()
    }

    /// Every pane in window order for the backend's `CTL_REQUEST_SNAPSHOT`,
    /// with at most `max_history_lines` lines of history each.
    pub fn snapshot(&mut self, max_history_lines: usize) -> Vec<backend::PaneSnapshot> {
        let Some(layout) = &self.layout else {
            return Vec::new();
        };
        let ids: Vec<i64> = layout
            .windows
            .iter()
            .flat_map(|w| w.panes.iter().map(|p| p.id))
            .collect();
        ids.into_iter()
            .filter_map(|id| {
                let pane = self.panes.get_mut(&id)?;
                Some(snapshot::capture(&mut pane.parser, id, max_history_lines))
            })
            .collect()
    }

    fn host_resize(&mut self) -> Vec<Outgoing<P>> {
        let size = self.host_pane_size();
        if self.host_size == Some(size) {
            return Vec::new();
        }
        self.host_size = Some(size);
        let mut enc = Encoder::new();
        proto::encode_resize(&mut enc, size.0, size.1);
        self.to_host(enc)
    }

    /// Creates, resizes and drops panes to match the layout, and tracks
    /// the last window for the status line.
    fn apply_layout(&mut self, layout: &Layout) {
        let mut keep = BTreeSet::new();
        for pane in layout.windows.iter().flat_map(|w| &w.panes) {
            if keep.len() >= MAX_PANES {
                break;
            }
            let rows = clamp_dim(pane.sy);
            let cols = clamp_dim(pane.sx);
            match self.panes.get_mut(&pane.id) {
                Some(p) => {
                    if p.size() != (rows, cols) {
                        p.resize(rows, cols);
                    }
                }
                None => {
                    self.panes.insert(pane.id, Pane::new(rows, cols));
                }
            }
            keep.insert(pane.id);
        }
        self.panes.retain(|id, _| keep.contains(id));
        let previous = self.layout.as_ref().map(|l| l.active_window);
        if previous.is_some() && previous != Some(layout.active_window) {
            self.last_window = previous;
        }
        if self
            .last_window
            .is_some_and(|idx| !layout.windows.iter().any(|w| w.idx == idx))
        {
            self.last_window = None;
        }
        self.layout = Some(layout.clone());
    }

    /// A command replicated from the host (`EXEC_CMD`): key bindings and
    /// options are mirrored, anything else is the host's own business.
    fn replicated_command(&mut self, args: &[String]) -> Vec<Outgoing<P>> {
        let Some(name) = args.first() else {
            return Vec::new();
        };
        match crate::commands::resolve(name) {
            Ok("bind-key") | Ok("unbind-key") => {
                if let Err(e) = self.tables.apply(args) {
                    debug!(error = %e, ?args, "ignoring replicated key binding");
                }
            }
            Ok("set-option") | Ok("set-window-option") => {
                self.set_option(args);
                return self.named_session_warning(args);
            }
            _ => {}
        }
        Vec::new()
    }

    /// `handle_session_name_options`: without a backend nobody can honour
    /// `tmate-session-name`, `tmate-session-name-ro` or `tmate-api-key`,
    /// so the host is told once.
    fn named_session_warning(&mut self, args: &[String]) -> Vec<Outgoing<P>> {
        let Some((name, _)) = set_option_args(args) else {
            return Vec::new();
        };
        if self.backend
            || self.named_session_warned
            || !matches!(
                name,
                "tmate-session-name" | "tmate-session-name-ro" | "tmate-api-key"
            )
        {
            return Vec::new();
        }
        self.named_session_warned = true;
        let mut enc = Encoder::new();
        proto::encode_notify(&mut enc, NAMED_SESSIONS_UNSUPPORTED_MSG);
        self.to_host(enc)
    }

    /// `set-option`/`set-window-option`: the authorized-keys options the
    /// old server hooked (`tmate_hook_set_option_auth`), plus the options
    /// that shape what viewers see and how their keys are read.
    fn set_option(&mut self, args: &[String]) {
        let Some((name, value)) = set_option_args(args) else {
            return;
        };
        match name {
            "tmate-authorized-keys" => {
                self.authorized_keys = Some(Vec::new());
                self.keys_generation += 1;
            }
            "tmate-set" => {
                if let Some(line) = value.strip_prefix("authorized_keys=") {
                    match PublicKey::from_openssh(line) {
                        Ok(key) => {
                            self.authorized_keys.get_or_insert_with(Vec::new).push(key);
                            self.keys_generation += 1;
                        }
                        Err(e) => debug!(error = %e, "ignoring unparsable authorized key"),
                    }
                }
            }
            "status-left-length" => {
                if let Ok(n) = value.parse() {
                    self.status_left_length = n;
                }
            }
            "status-right-length" => {
                if let Ok(n) = value.parse() {
                    self.status_right_length = n;
                }
            }
            _ => {
                self.options.set(name, value);
            }
        }
    }

    fn active_window(&self) -> Option<&proto::WindowLayout> {
        let layout = self.layout.as_ref()?;
        layout
            .windows
            .iter()
            .find(|w| w.idx == layout.active_window)
    }

    #[cfg(test)]
    fn active_pane_id(&self) -> Option<i64> {
        self.active_window().map(|w| w.active_pane)
    }

    fn format_values(&self) -> FormatValues {
        match self.active_window() {
            Some(w) => FormatValues {
                window_name: w.name.clone(),
                window_idx: w.idx,
                pane_idx: w
                    .panes
                    .iter()
                    .position(|p| p.id == w.active_pane)
                    .unwrap_or(0),
            },
            None => FormatValues {
                window_name: String::new(),
                window_idx: 0,
                pane_idx: 0,
            },
        }
    }

    fn window_entries(&self) -> Vec<WindowEntry> {
        let Some(layout) = &self.layout else {
            return Vec::new();
        };
        layout
            .windows
            .iter()
            .map(|w| WindowEntry {
                idx: w.idx,
                name: w.name.clone(),
                current: w.idx == layout.active_window,
                last: Some(w.idx) == self.last_window,
            })
            .collect()
    }

    fn render_all(&mut self) -> Vec<Outgoing<P>> {
        let ids: Vec<ViewerId> = self.viewers.keys().copied().collect();
        ids.into_iter()
            .flat_map(|id| self.render_one(id, false))
            .collect()
    }

    /// Composes the viewer's screen: the active window's panes at their
    /// offsets, borders, pane numbers, then the status row (prompt or
    /// message when one is up) and the cursor.
    fn compose(&mut self, id: ViewerId) -> Option<Canvas> {
        let v = self.viewers.get(&id)?;
        let size = v.size;
        let (identify, has_overlay) = (v.identify, v.prompt.is_some() || v.message.is_some());
        let mut canvas = Canvas::new(size);
        let area_rows = if size.rows >= 2 {
            size.rows - 1
        } else {
            size.rows
        };
        let mut cursor = None;

        let window = self.active_window().cloned();
        if let Some(w) = window {
            let rects: Vec<PaneRect> = w
                .panes
                .iter()
                .map(|g| PaneRect {
                    xoff: g.xoff.clamp(0, i64::from(u16::MAX)) as u16,
                    yoff: g.yoff.clamp(0, i64::from(u16::MAX)) as u16,
                    sx: clamp_dim(g.sx),
                    sy: clamp_dim(g.sy),
                })
                .collect();
            let active = w
                .panes
                .iter()
                .position(|g| g.id == w.active_pane)
                .unwrap_or(0);
            for (i, (geom, rect)) in w.panes.iter().zip(&rects).enumerate() {
                let Some(pane) = self.panes.get_mut(&geom.id) else {
                    continue;
                };
                let (cells, pane_cursor) = pane.draw();
                for (r, row) in cells.iter().enumerate().take(usize::from(rect.sy)) {
                    let Some(y) = u16::try_from(usize::from(rect.yoff) + r)
                        .ok()
                        .filter(|y| *y < area_rows)
                    else {
                        break;
                    };
                    for (c, cell) in row.iter().enumerate().take(usize::from(rect.sx)) {
                        if let Ok(x) = u16::try_from(usize::from(rect.xoff) + c) {
                            canvas.set(y, x, *cell);
                        }
                    }
                }
                if i == active {
                    cursor = pane_cursor.and_then(|(r, c)| {
                        let y = rect.yoff.checked_add(r)?;
                        let x = rect.xoff.checked_add(c)?;
                        (y < area_rows && x < size.cols).then_some((y, x))
                    });
                }
            }
            let layout = self.layout.as_ref()?;
            let window = Window::new(
                layout.sx.clamp(0, i64::from(u16::MAX)) as u16,
                layout.sy.clamp(0, i64::from(u16::MAX)) as u16,
                &rects,
                active,
            );
            layout::draw_borders(&mut canvas, area_rows, &window);
            if identify {
                for (i, rect) in rects.iter().enumerate() {
                    layout::draw_pane_number(&mut canvas, rect, i, i == active);
                }
            }
        }

        if size.rows >= 2 {
            let windows = self.window_entries();
            let v = self.viewers.get(&id)?;
            let cols = usize::from(size.cols);
            let cells = if let Some(prompt) = &v.prompt {
                prompt.render(cols)
            } else if let Some(message) = &v.message {
                render::message_row(message, cols)
            } else {
                StatusLine {
                    left: &self.status_left,
                    right: &self.status_right,
                    windows: &windows,
                    left_length: self.status_left_length,
                    right_length: self.status_right_length,
                }
                .render(cols)
            };
            canvas.put_cells(size.rows - 1, 0, &cells);
        }
        canvas.cursor = if has_overlay { None } else { cursor };
        Some(canvas)
    }

    /// Draws one viewer's screen as a diff against what it last saw, or
    /// in full when `full` or nothing is known about its terminal.
    fn render_one(&mut self, id: ViewerId, full: bool) -> Vec<Outgoing<P>> {
        let Some(canvas) = self.compose(id) else {
            return Vec::new();
        };
        let Some(v) = self.viewers.get_mut(&id) else {
            return Vec::new();
        };
        let bytes = match &v.last {
            Some(prev) if !full && prev.size() == canvas.size() => canvas.render_diff(prev),
            _ => canvas.render_full(),
        };
        v.last = Some(canvas);
        if bytes.is_empty() {
            return Vec::new();
        }
        vec![Outgoing {
            to: v.peer.clone(),
            payload: Payload::Data(Bytes::from(bytes)),
        }]
    }
}

fn ended_notice<P>(peer: P) -> Vec<Outgoing<P>>
where
    P: Clone,
{
    vec![
        Outgoing {
            to: peer.clone(),
            payload: Payload::Data(Bytes::from_static(SESSION_ENDED)),
        },
        Outgoing {
            to: peer,
            payload: Payload::Close,
        },
    ]
}

fn clamp_dim(n: i64) -> u16 {
    n.clamp(1, i64::from(MAX_PANE_DIM)) as u16
}

fn clamp_size(size: Size) -> Size {
    Size {
        cols: size.cols.clamp(1, MAX_VIEWER_DIM),
        rows: size.rows.clamp(1, MAX_VIEWER_DIM),
    }
}

/// Picks `(name, value)` out of a replicated `set-option` argv, skipping
/// tmux's flags (`-g`, `-t target`, ...).
fn set_option_args(args: &[String]) -> Option<(&str, &str)> {
    let (cmd, rest) = args.split_first()?;
    if !matches!(
        cmd.as_str(),
        "set-option" | "set" | "set-window-option" | "setw"
    ) {
        return None;
    }
    let mut positional = Vec::with_capacity(2);
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        if arg == "-t" {
            iter.next();
        } else if arg.starts_with('-') && arg.len() > 1 {
            continue;
        } else {
            positional.push(arg.as_str());
        }
    }
    match positional[..] {
        [name, value, ..] => Some((name, value)),
        [name] => Some((name, "")),
        [] => None,
    }
}

/// Where output for one connection goes: an ordered queue drained by a
/// task that writes to the SSH channel (or, in a worker, to the gateway).
/// Queueing never blocks, so the hub can be used from inside russh
/// handlers without risking a deadlock between two connections' event
/// loops. A peer that does not drain its queue is cut off once more than
/// `MAX_QUEUED` bytes wait for it, so a stalled viewer cannot make the
/// server hold its screen updates forever.
#[derive(Clone, Debug)]
pub struct Peer {
    tx: mpsc::UnboundedSender<Payload>,
    queued: Arc<AtomicUsize>,
    kicked: Arc<AtomicBool>,
    /// Fired when the peer is kicked, for a writer parked in a send.
    kick: Arc<Notify>,
}

/// Bytes a peer may have queued before it is closed.
pub const MAX_QUEUED: usize = 8 * 1024 * 1024;

/// How long a peer gets to take a channel close, and then to close its
/// connection, before the connection is cut.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The receiving end of a `Peer`; whoever drains it does the writing.
pub struct PeerRx {
    rx: mpsc::UnboundedReceiver<Payload>,
    queued: Arc<AtomicUsize>,
    kick: Arc<Notify>,
}

impl PeerRx {
    pub async fn recv(&mut self) -> Option<Payload> {
        let payload = self.rx.recv().await?;
        self.account(&payload);
        Some(payload)
    }

    /// What is queued right now, if anything.
    #[cfg(test)]
    pub fn try_recv(&mut self) -> Option<Payload> {
        let payload = self.rx.try_recv().ok()?;
        self.account(&payload);
        Some(payload)
    }

    fn account(&self, payload: &Payload) {
        if let Payload::Data(d) = payload {
            self.queued.fetch_sub(d.len(), Ordering::Relaxed);
        }
    }
}

/// What the writer task needs from an SSH session: a
/// `russh::server::Handle` in the gateway, a recorder in tests.
pub trait ChannelSink: Send + Sync + 'static {
    fn data(&self, data: Bytes) -> impl Future<Output = Result<(), ()>> + Send;
    fn eof(&self) -> impl Future<Output = ()> + Send;
    fn close(&self) -> impl Future<Output = ()> + Send;
}

struct SshChannel {
    handle: Handle,
    channel: ChannelId,
}

impl ChannelSink for SshChannel {
    async fn data(&self, data: Bytes) -> Result<(), ()> {
        self.handle.data(self.channel, data).await.map_err(|_| ())
    }

    async fn eof(&self) {
        let _ = self.handle.eof(self.channel).await;
    }

    async fn close(&self) {
        let _ = self.handle.close(self.channel).await;
    }
}

impl Peer {
    /// A peer whose output the caller drains from the returned receiver.
    pub fn new() -> (Peer, PeerRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let kick = Arc::new(Notify::new());
        let peer = Peer {
            tx,
            queued: queued.clone(),
            kicked: Arc::new(AtomicBool::new(false)),
            kick: kick.clone(),
        };
        (peer, PeerRx { rx, queued, kick })
    }

    /// A peer written to an SSH channel by a task of its own. `cut` ends
    /// the connection when the peer stops taking what it is sent.
    pub fn spawn(handle: Handle, channel: ChannelId, cut: Cut) -> Peer {
        let (peer, rx) = Peer::new();
        tokio::spawn(write_peer(rx, SshChannel { handle, channel }, cut));
        peer
    }

    pub fn send(&self, payload: Payload) {
        if self.kicked.load(Ordering::Relaxed) {
            return;
        }
        if let Payload::Data(d) = &payload {
            let queued = self.queued.fetch_add(d.len(), Ordering::Relaxed) + d.len();
            if queued > MAX_QUEUED {
                // Too far behind: the connection is closed instead of
                // letting its backlog grow. The receiver sees Close next,
                // and a writer stuck in a send is woken to cut.
                self.kicked.store(true, Ordering::Relaxed);
                debug!(queued, "peer is not draining its output; closing it");
                let _ = self.tx.send(Payload::Close);
                self.kick.notify_one();
                return;
            }
        }
        // A closed receiver means the connection is gone; nothing to do.
        let _ = self.tx.send(payload);
    }

    /// Whether the peer was cut off for not draining its queue.
    #[cfg(test)]
    pub fn is_kicked(&self) -> bool {
        self.kicked.load(Ordering::Relaxed)
    }
}

/// Drains `rx` into `sink`. A send to a session goes through a bounded
/// queue that the session loop stops draining while the channel is
/// window-blocked, so every way the peer can stall ends with its
/// connection cut: at once when it was kicked for not draining, after
/// `CLOSE_GRACE` when it will not take a close or will not act on one.
async fn write_peer<S: ChannelSink>(mut rx: PeerRx, sink: S, cut: Cut) {
    let kick = rx.kick.clone();
    let write = async {
        while let Some(payload) = rx.recv().await {
            match payload {
                Payload::Data(data) => {
                    if sink.data(data).await.is_err() {
                        return;
                    }
                }
                Payload::Close => {
                    let polite = async {
                        sink.eof().await;
                        sink.close().await;
                    };
                    if tokio::time::timeout(CLOSE_GRACE, polite).await.is_err() {
                        debug!("peer did not take the channel close; cutting its connection");
                        cut.cut();
                    } else {
                        // One channel per connection: once it is closed
                        // the connection has no further use, so a client
                        // that keeps it open is cut.
                        cut.cut_after(CLOSE_GRACE);
                    }
                    return;
                }
            }
        }
    };
    tokio::select! {
        biased;
        () = kick.notified() => {
            debug!("peer is not draining its output; cutting its connection");
            cut.cut();
        }
        () = write => {}
    }
}

/// The handle both connection types hold for one session: a `State` under
/// a mutex, with output delivered after the lock is released.
pub struct Hub {
    state: Mutex<State<Peer>>,
    me: Weak<Hub>,
}

impl Hub {
    pub fn new(keys_required: bool, backend: bool) -> Arc<Hub> {
        let mut state = State::new(keys_required);
        state.set_backend(backend);
        Arc::new_cyclic(|me| Hub {
            state: Mutex::new(state),
            me: me.clone(),
        })
    }

    /// A fresh session that a host resumed with valid reconnection data
    /// after its previous session was already gone: same tokens, new state.
    pub fn new_reconnected(keys_required: bool, backend: bool) -> Arc<Hub> {
        let hub = Hub::new(keys_required, backend);
        hub.run(|s| (s.mark_reconnected(), Vec::new()));
        hub
    }

    /// Runs `f` under the lock and delivers its output afterwards.
    fn run<R>(&self, f: impl FnOnce(&mut State<Peer>) -> (R, Vec<Outgoing<Peer>>)) -> R {
        let (result, out, timers) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let (result, out) = f(&mut state);
            (result, out, state.take_timers())
        };
        self.deliver(out, timers);
        result
    }

    /// Sends the output and schedules the timers. Not generic, so the
    /// task a timer spawns does not nest a new instantiation of `run`.
    fn deliver(&self, out: Vec<Outgoing<Peer>>, timers: Vec<Timer>) {
        for o in out {
            o.to.send(o.payload);
        }
        if timers.is_empty() {
            return;
        }
        let (Ok(runtime), Some(hub)) = (tokio::runtime::Handle::try_current(), self.me.upgrade())
        else {
            return;
        };
        for timer in timers {
            let hub = hub.clone();
            let after = match &timer {
                Timer::Message { after, .. } | Timer::Identify { after, .. } => *after,
            };
            runtime.spawn(async move {
                tokio::time::sleep(after).await;
                hub.timer_fired(timer);
            });
        }
    }

    fn timer_fired(&self, timer: Timer) {
        self.run(|s| ((), s.timer_fired(&timer)));
    }

    fn with<R>(&self, f: impl FnOnce(&State<Peer>) -> R) -> R {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        f(&state)
    }

    pub fn set_host(&self, peer: Peer) {
        self.run(|s| (s.set_host(peer), Vec::new()));
    }

    pub fn host_peer(&self) -> Option<Peer> {
        self.with(|s| s.host().cloned())
    }

    /// Bytes for the host, in order with everything else the hub sends it.
    pub fn send_host(&self, data: Bytes) {
        if let Some(host) = self.host_peer() {
            host.send(Payload::Data(data));
        }
    }

    pub fn close_host(&self) {
        if let Some(host) = self.host_peer() {
            host.send(Payload::Close);
        }
    }

    /// A reconnecting host took the session over: the old host connection
    /// is closed and viewers are told.
    pub fn host_adopted(&self, peer: Peer) {
        self.run(|s| ((), s.host_adopted(peer)));
    }

    pub fn host_msg(&self, msg: &HostMsg) {
        self.run(|s| ((), s.host_msg(msg)));
    }

    pub fn keys_enabled(&self) -> bool {
        self.with(State::keys_enabled)
    }

    pub fn authorized_key_count(&self) -> usize {
        self.with(|s| s.authorized_keys().map_or(0, <[PublicKey]>::len))
    }

    /// The key list with its generation; see `State::keys_generation`.
    pub fn authorized_keys(&self) -> (u64, Option<Vec<PublicKey>>) {
        self.with(|s| {
            (
                s.keys_generation(),
                s.authorized_keys().map(<[PublicKey]>::to_vec),
            )
        })
    }

    pub fn missing_required_keys(&self) -> bool {
        self.with(State::missing_required_keys)
    }

    pub fn authorize(&self, key: Option<&PublicKey>) -> bool {
        self.with(|s| s.authorize(key))
    }

    pub fn num_clients(&self) -> usize {
        self.with(State::num_clients)
    }

    pub fn is_ended(&self) -> bool {
        self.with(State::is_ended)
    }

    /// Whether this hub's host reconnected to the session; true once.
    pub fn take_reconnected(&self) -> bool {
        self.run(|s| (s.take_reconnected(), Vec::new()))
    }

    /// The host sent READY: resends the size when the host reconnected.
    pub fn host_ready(&self) {
        self.run(|s| ((), s.host_ready()));
    }

    pub fn attach_viewer(&self, id: ViewerId, peer: Peer, access: Access, ip: &str, size: Size) {
        self.run(|s| ((), s.attach_viewer_as(id, peer, access, ip, size)));
    }

    pub fn detach_viewer(&self, id: ViewerId) {
        self.run(|s| ((), s.detach_viewer(id)));
    }

    pub fn resize_viewer(&self, id: ViewerId, size: Size) {
        self.run(|s| ((), s.resize_viewer(id, size)));
    }

    /// Returns the generation to pass to `flush_viewer` when an ESC is held.
    pub fn viewer_input(&self, id: ViewerId, data: &[u8]) -> Option<u64> {
        self.run(|s| {
            let (out, pending) = s.viewer_input(id, data);
            (pending, out)
        })
    }

    pub fn flush_viewer(&self, id: ViewerId, generation: u64) {
        self.run(|s| ((), s.flush_viewer(id, generation)));
    }

    /// The host is gone: viewers are told and dropped.
    pub fn end(&self) {
        self.run(|s| ((), s.end()));
    }

    /// The backend's web clients changed size (`CTL_RESIZE`).
    pub fn backend_resize(&self, sx: i64, sy: i64) {
        self.run(|s| ((), s.backend_resize(sx, sy)));
    }

    /// The panes for a `CTL_REQUEST_SNAPSHOT`.
    pub fn snapshot(&self, max_history_lines: usize) -> Vec<backend::PaneSnapshot> {
        self.run(|s| (s.snapshot(max_history_lines), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Special;
    use crate::msgpack::{Decoder, Value};
    use crate::proto::{PaneGeom, WindowLayout};

    const HOST: &str = "host";

    fn state() -> State<&'static str> {
        let mut s = State::new(false);
        s.set_host(HOST);
        s
    }

    fn size(cols: u16, rows: u16) -> Size {
        Size { cols, rows }
    }

    fn layout(panes: &[(i64, i64, i64)], active: i64) -> HostMsg {
        HostMsg::SyncLayout(Layout {
            sx: 80,
            sy: 23,
            windows: vec![WindowLayout {
                idx: 0,
                name: "bash".into(),
                panes: panes
                    .iter()
                    .map(|&(id, sx, sy)| PaneGeom {
                        id,
                        sx,
                        sy,
                        xoff: 0,
                        yoff: 0,
                    })
                    .collect(),
                active_pane: active,
            }],
            active_window: 0,
        })
    }

    /// Decodes every message addressed to the host.
    fn host_msgs(out: &[Outgoing<&'static str>]) -> Vec<Value> {
        let mut d = Decoder::new();
        for o in out.iter().filter(|o| o.to == HOST) {
            if let Payload::Data(b) = &o.payload {
                d.feed(b);
            }
        }
        let mut values = Vec::new();
        while let Some(v) = d.next_value().unwrap() {
            values.push(v);
        }
        values
    }

    fn resize_of(out: &[Outgoing<&'static str>]) -> Option<(i64, i64)> {
        host_msgs(out)
            .into_iter()
            .find_map(|v| match v.as_array()? {
                [Value::Int(2), Value::Int(sx), Value::Int(sy)] => Some((*sx, *sy)),
                _ => None,
            })
    }

    fn notices(out: &[Outgoing<&'static str>]) -> Vec<String> {
        host_msgs(out)
            .into_iter()
            .filter_map(|v| match v.as_array()? {
                [Value::Int(0), Value::Bytes(s)] => Some(String::from_utf8_lossy(s).into_owned()),
                _ => None,
            })
            .collect()
    }

    fn set_env_of(out: &[Outgoing<&'static str>], name: &str) -> Option<String> {
        host_msgs(out)
            .into_iter()
            .find_map(|v| match v.as_array()? {
                [Value::Int(4), Value::Bytes(n), Value::Bytes(val)] if n == name.as_bytes() => {
                    Some(String::from_utf8_lossy(val).into_owned())
                }
                _ => None,
            })
    }

    fn pane_keys(out: &[Outgoing<&'static str>]) -> Vec<u64> {
        host_msgs(out)
            .into_iter()
            .filter_map(|v| match v.as_array()? {
                [Value::Int(6), Value::Int(-1), Value::Int(k)] => Some(*k as u64),
                _ => None,
            })
            .collect()
    }

    /// `(client_id, argv)` of every EXEC_CMD sent to the host.
    fn exec_cmds(out: &[Outgoing<&'static str>]) -> Vec<(i64, Vec<String>)> {
        host_msgs(out)
            .into_iter()
            .filter_map(|v| match v.as_array()? {
                [Value::Int(7), Value::Int(id), rest @ ..] => Some((
                    *id,
                    rest.iter()
                        .map(|a| String::from_utf8_lossy(a.as_bytes().unwrap()).into_owned())
                        .collect(),
                )),
                _ => None,
            })
            .collect()
    }

    fn viewer_bytes(out: &[Outgoing<&'static str>], to: &str) -> Vec<u8> {
        out.iter()
            .filter(|o| o.to == to)
            .filter_map(|o| match &o.payload {
                Payload::Data(b) => Some(b.as_ref()),
                Payload::Close => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// What a viewer's terminal shows after receiving `out` on top of `term`.
    fn screen_rows(
        term: &mut vt100::Parser,
        out: &[Outgoing<&'static str>],
        to: &str,
    ) -> Vec<String> {
        term.process(&viewer_bytes(out, to));
        let cols = term.screen().size().1;
        term.screen()
            .rows(0, cols)
            .map(|r| r.trim_end().to_string())
            .collect()
    }

    fn status_row(s: &State<&'static str>, id: ViewerId) -> String {
        let v = &s.viewers[&id];
        let last = v.last.as_ref().unwrap();
        last.row_text(last.size().rows - 1)
    }

    fn type_at(
        s: &mut State<&'static str>,
        id: ViewerId,
        data: &[u8],
        now: Instant,
    ) -> Vec<Outgoing<&'static str>> {
        s.viewer_input_at(id, data, now).0
    }

    #[test]
    fn size_follows_smallest_read_write_viewer() {
        let mut s = state();
        let (a, out) = s.attach_viewer("a", Access::ReadWrite, "1.1.1.1", size(80, 24));
        assert_eq!(resize_of(&out), Some((80, 23)));

        let (_, out) = s.attach_viewer("ro", Access::ReadOnly, "2.2.2.2", size(40, 10));
        assert_eq!(
            resize_of(&out),
            None,
            "read-only viewers do not shrink the host"
        );
        assert_eq!(s.host_pane_size(), (80, 23));

        let (b, out) = s.attach_viewer("b", Access::ReadWrite, "3.3.3.3", size(100, 20));
        assert_eq!(resize_of(&out), Some((80, 19)));

        let out = s.detach_viewer(a.unwrap());
        assert_eq!(resize_of(&out), Some((100, 19)));

        let out = s.resize_viewer(b.unwrap(), size(60, 2));
        assert_eq!(resize_of(&out), Some((60, 1)));
        let out = s.resize_viewer(b.unwrap(), size(60, 1));
        assert_eq!(resize_of(&out), None, "a one-row terminal keeps its row");
        assert_eq!(s.host_pane_size(), (60, 1));

        let out = s.detach_viewer(b.unwrap());
        assert_eq!(resize_of(&out), Some((-1, -1)), "no read-write viewer left");

        let (_, out) = s.attach_viewer("huge", Access::ReadWrite, "4.4.4.4", size(5000, 5000));
        assert_eq!(resize_of(&out), Some((500, 499)));
    }

    #[test]
    fn join_and_leave_notices() {
        let mut s = state();
        let (a, out) = s.attach_viewer("a", Access::ReadWrite, "10.0.0.1", size(80, 24));
        assert_eq!(set_env_of(&out, "tmate_num_clients").as_deref(), Some("1"));
        assert_eq!(
            notices(&out),
            vec!["A mate has joined (10.0.0.1) -- 1 client currently connected"]
        );

        let (b, out) = s.attach_viewer("b", Access::ReadOnly, "10.0.0.2", size(80, 24));
        assert_eq!(set_env_of(&out, "tmate_num_clients").as_deref(), Some("2"));
        assert_eq!(
            notices(&out),
            vec!["A mate has joined (10.0.0.2) -- 2 clients currently connected"]
        );
        assert_eq!(s.num_clients(), 2);

        let out = s.detach_viewer(a.unwrap());
        assert_eq!(set_env_of(&out, "tmate_num_clients").as_deref(), Some("1"));
        assert_eq!(
            notices(&out),
            vec!["A mate has left (10.0.0.1) -- 1 client currently connected"]
        );

        let out = s.detach_viewer(b.unwrap());
        assert_eq!(set_env_of(&out, "tmate_num_clients").as_deref(), Some("0"));
        assert_eq!(
            notices(&out),
            vec!["A mate has left (10.0.0.2) -- 0 client currently connected"]
        );
        assert!(
            s.detach_viewer(b.unwrap()).is_empty(),
            "detaching twice is harmless"
        );
    }

    fn test_key() -> PublicKey {
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn exec(args: &[&str]) -> HostMsg {
        HostMsg::ExecCmd(args.iter().map(|a| a.to_string()).collect())
    }

    #[test]
    fn authorized_keys_gate_viewers() {
        let listed = test_key();
        let other = test_key();
        let mut s = state();
        assert!(s.authorize(None));
        assert!(s.authorize(Some(&other)));
        assert!(!s.missing_required_keys());

        s.host_msg(&exec(&[
            "set-option",
            "-g",
            "tmate-authorized-keys",
            "/home/me/.ssh/authorized_keys",
        ]));
        assert!(s.keys_enabled());
        assert!(!s.authorize(None), "an enabled empty list admits nobody");
        assert!(!s.authorize(Some(&listed)));

        s.host_msg(&exec(&[
            "set-option",
            "tmate-set",
            "authorized_keys=garbage",
        ]));
        let line = format!(
            "authorized_keys={} comment here",
            listed.to_openssh().unwrap()
        );
        s.host_msg(&exec(&["set", "-t", "x", "tmate-set", &line]));
        assert!(s.authorize(Some(&listed)));
        assert!(!s.authorize(Some(&other)));
        assert!(!s.authorize(None));

        // Enabling again resets the list, as the old server did.
        s.host_msg(&exec(&["set-option", "tmate-authorized-keys", "/x"]));
        assert!(!s.authorize(Some(&listed)));

        // Other options are ignored.
        s.host_msg(&exec(&["set-option", "status-left", "x"]));
        assert!(s.keys_enabled());
    }

    #[test]
    fn authorized_keys_only_requires_a_list() {
        let mut s: State<&'static str> = State::new(true);
        assert!(s.missing_required_keys());
        s.host_msg(&exec(&["set-option", "tmate-authorized-keys", "/x"]));
        assert!(!s.missing_required_keys());
    }

    #[test]
    fn layout_creates_resizes_and_removes_panes() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23), (1, 40, 23)], 0));
        assert_eq!(s.pane_count(), 2);
        assert_eq!(s.pane_size(0), Some((23, 80)));
        assert_eq!(s.pane_size(1), Some((23, 40)));

        s.host_msg(&layout(&[(1, 9000, 0)], 1));
        assert_eq!(s.pane_count(), 1);
        assert_eq!(s.pane_size(0), None);
        assert_eq!(s.pane_size(1), Some((1, 500)), "sizes are clamped");
        assert_eq!(s.active_pane_id(), Some(1));

        // Panes beyond the cap are ignored rather than allocated.
        let many: Vec<(i64, i64, i64)> = (0..(MAX_PANES as i64 + 5)).map(|i| (i, 2, 2)).collect();
        s.host_msg(&layout(&many, 0));
        assert_eq!(s.pane_count(), MAX_PANES);
    }

    #[test]
    fn pty_data_produces_frames_for_viewers() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        s.host_msg(&HostMsg::Status {
            left: "[default] ".into(),
            right: "".into(),
        });

        let (id, out) = s.attach_viewer("v", Access::ReadWrite, "1.2.3.4", size(80, 24));
        let full = viewer_bytes(&out, "v");
        assert!(
            full.starts_with(b"\x1b[?25l\x1b[0m\x1b[H\x1b[2J"),
            "join starts with a full frame"
        );
        assert!(String::from_utf8_lossy(&full).contains("[default] 0:bash*"));

        let out = s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"hello".to_vec(),
        });
        let diff = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(diff.contains("hello"));
        assert!(
            !diff.contains("\x1b[2J"),
            "a diff does not clear the screen"
        );
        assert!(
            !diff.contains("[default]"),
            "unchanged status is not redrawn"
        );

        let out = s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b" world".to_vec(),
        });
        let diff = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(
            diff.contains("world") && !diff.contains("hello"),
            "{diff:?}"
        );

        // Data for a pane in another window draws nothing.
        s.host_msg(&HostMsg::SyncLayout(Layout {
            sx: 80,
            sy: 23,
            windows: vec![
                WindowLayout {
                    idx: 0,
                    name: "bash".into(),
                    panes: vec![PaneGeom {
                        id: 0,
                        sx: 80,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    }],
                    active_pane: 0,
                },
                WindowLayout {
                    idx: 1,
                    name: "vim".into(),
                    panes: vec![PaneGeom {
                        id: 1,
                        sx: 80,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    }],
                    active_pane: 1,
                },
            ],
            active_window: 0,
        }));
        let out = s.host_msg(&HostMsg::PtyData {
            pane: 1,
            data: b"hidden".to_vec(),
        });
        assert!(viewer_bytes(&out, "v").is_empty());
        assert!(
            s.host_msg(&HostMsg::PtyData {
                pane: 99,
                data: b"x".to_vec()
            })
            .is_empty()
        );

        // A status change alone redraws the status row.
        let out = s.host_msg(&HostMsg::Status {
            left: "[other] ".into(),
            right: "".into(),
        });
        assert!(
            String::from_utf8_lossy(&viewer_bytes(&out, "v")).contains("other] "),
            "only the changed cells are redrawn"
        );

        // Switching windows shows the other pane and marks the last window.
        let out = s.host_msg(&HostMsg::SyncLayout(Layout {
            sx: 80,
            sy: 23,
            windows: vec![
                WindowLayout {
                    idx: 0,
                    name: "bash".into(),
                    panes: vec![PaneGeom {
                        id: 0,
                        sx: 80,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    }],
                    active_pane: 0,
                },
                WindowLayout {
                    idx: 1,
                    name: "vim".into(),
                    panes: vec![PaneGeom {
                        id: 1,
                        sx: 80,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    }],
                    active_pane: 1,
                },
            ],
            active_window: 1,
        }));
        assert!(!viewer_bytes(&out, "v").is_empty());
        let last = s.viewers[&id.unwrap()].last.as_ref().unwrap();
        assert_eq!(last.rows_text()[0], "hidden");
        assert_eq!(status_row(&s, id.unwrap()), "[other] 0:bash- 1:vim*");

        let out = s.resize_viewer(id.unwrap(), size(100, 30));
        assert!(
            viewer_bytes(&out, "v").starts_with(b"\x1b[?25l\x1b[0m\x1b[H\x1b[2J"),
            "resize resends a full frame"
        );
    }

    #[test]
    fn panes_are_laid_out_with_borders() {
        let mut s = state();
        s.host_msg(&HostMsg::SyncLayout(Layout {
            sx: 80,
            sy: 23,
            windows: vec![WindowLayout {
                idx: 0,
                name: "sh".into(),
                panes: vec![
                    PaneGeom {
                        id: 0,
                        sx: 40,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    },
                    PaneGeom {
                        id: 1,
                        sx: 39,
                        sy: 23,
                        xoff: 41,
                        yoff: 0,
                    },
                ],
                active_pane: 1,
            }],
            active_window: 0,
        }));
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"sh-3.2$".to_vec(),
        });
        s.host_msg(&HostMsg::PtyData {
            pane: 1,
            data: b"echo pane-two\r\n$ ".to_vec(),
        });
        let mut term = vt100::Parser::new(24, 80, 0);
        let (_, out) = s.attach_viewer("v", Access::ReadWrite, "1.2.3.4", size(80, 24));
        let rows = screen_rows(&mut term, &out, "v");
        assert_eq!(rows[0], format!("sh-3.2${}│echo pane-two", " ".repeat(33)));
        assert_eq!(rows[1], format!("{}│$", " ".repeat(40)));
        assert_eq!(rows[22], format!("{}│", " ".repeat(40)));
        assert_eq!(rows[23], "0:sh*");
        // Cursor comes from the active pane, offset by its position.
        assert_eq!(term.screen().cursor_position(), (1, 43));

        // A bigger viewer sees the window's edge, dots and the size note.
        let mut big = vt100::Parser::new(30, 100, 0);
        let (_, out) = s.attach_viewer("big", Access::ReadWrite, "1.2.3.5", size(100, 30));
        let rows = screen_rows(&mut big, &out, "big");
        assert_eq!(
            rows[0],
            format!(
                "sh-3.2${}│echo pane-two{}│{}",
                " ".repeat(33),
                " ".repeat(26),
                "·".repeat(19)
            )
        );
        assert_eq!(
            rows[23],
            format!("{}┴{}┘{}", "─".repeat(40), "─".repeat(39), "·".repeat(19))
        );
        assert_eq!(
            rows[28],
            format!("{}(size 80x23 from a smaller client)", "·".repeat(66))
        );
    }

    #[test]
    fn keys_go_to_the_host_from_read_write_viewers_only() {
        let mut s = state();
        let (rw, _) = s.attach_viewer("rw", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let (ro, _) = s.attach_viewer("ro", Access::ReadOnly, "2.2.2.2", size(80, 24));
        let rw = rw.unwrap();

        let (out, pending) = s.viewer_input(rw, b"a\x1b[A");
        assert_eq!(pane_keys(&out), vec![b'a' as u64, Special::Up.code()]);
        assert_eq!(pending, None);

        let (out, _) = s.viewer_input(ro.unwrap(), b"a");
        assert!(out.is_empty());

        let (out, pending) = s.viewer_input(rw, b"\x1b");
        assert!(out.is_empty());
        let generation = pending.expect("a lone ESC is held");
        // More input arrived: the old timer must not flush.
        let (out, _) = s.viewer_input(rw, b"x");
        assert_eq!(
            pane_keys(&out),
            vec![b'x' as u64 | crate::keys::KEYC_ESCAPE]
        );
        assert!(s.flush_viewer(rw, generation).is_empty());

        let (_, pending) = s.viewer_input(rw, b"\x1b");
        assert_eq!(pane_keys(&s.flush_viewer(rw, pending.unwrap())), vec![0x1b]);
    }

    #[test]
    fn prefix_bindings_dispatch_to_the_host_or_locally() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let id = id.unwrap();
        let t0 = Instant::now();
        let ms = Duration::from_millis;

        // C-b c -> new-window on the host, as argv with this viewer's id.
        let out = type_at(&mut s, id, b"\x02", t0);
        assert!(
            pane_keys(&out).is_empty() && exec_cmds(&out).is_empty(),
            "the prefix is swallowed"
        );
        let out = type_at(&mut s, id, b"c", t0 + ms(100));
        assert_eq!(exec_cmds(&out), vec![(1, vec!["new-window".to_string()])]);
        // C-b C-b -> send-prefix is forwarded like any other command.
        let out = type_at(&mut s, id, b"\x02\x02", t0 + ms(300));
        assert_eq!(exec_cmds(&out), vec![(1, vec!["send-prefix".to_string()])]);
        // Unbound key after the prefix: nothing at all.
        let out = type_at(&mut s, id, b"\x02", t0 + ms(500));
        assert!(out.is_empty());
        let out = type_at(&mut s, id, b"Z", t0 + ms(600));
        assert!(pane_keys(&out).is_empty() && exec_cmds(&out).is_empty());
        let out = type_at(&mut s, id, b"Z", t0 + ms(700));
        assert_eq!(pane_keys(&out), vec![b'Z' as u64]);
        // -r: Up again within repeat-time needs no prefix.
        let out = type_at(&mut s, id, b"\x02\x1b[A", t0 + ms(900));
        assert_eq!(
            exec_cmds(&out),
            vec![(1, vec!["select-pane".to_string(), "-U".to_string()])]
        );
        let out = type_at(&mut s, id, b"\x1b[A", t0 + ms(1000));
        assert_eq!(
            exec_cmds(&out),
            vec![(1, vec!["select-pane".to_string(), "-U".to_string()])]
        );
        let out = type_at(&mut s, id, b"\x1b[A", t0 + ms(2000));
        assert_eq!(pane_keys(&out), vec![Special::Up.code()], "repeat expired");
        // Host-replicated bindings and prefix apply on top of the defaults.
        s.host_msg(&exec(&["bind-key", "-n", "F5", "next-window"]));
        s.host_msg(&exec(&["set-option", "-g", "prefix", "C-a"]));
        let out = type_at(&mut s, id, b"\x1b[15~", t0 + ms(2100));
        assert_eq!(exec_cmds(&out), vec![(1, vec!["next-window".to_string()])]);
        let out = type_at(&mut s, id, b"\x02", t0 + ms(2200));
        assert_eq!(pane_keys(&out), vec![2], "C-b is plain with another prefix");
        let out = type_at(&mut s, id, b"\x01n", t0 + ms(2300));
        assert_eq!(exec_cmds(&out), vec![(1, vec!["next-window".to_string()])]);
        s.host_msg(&exec(&["unbind-key", "-n", "F5"]));
        let out = type_at(&mut s, id, b"\x1b[15~", t0 + ms(2400));
        assert_eq!(pane_keys(&out), vec![Special::F5.code()]);

        // C-a d -> detach-client closes the viewer locally.
        let out = type_at(&mut s, id, b"\x01d", t0 + ms(2500));
        assert!(
            out.iter()
                .any(|o| o.to == "v" && o.payload == Payload::Close)
        );
        assert!(notices(&out)[0].contains("A mate has left"));
        assert_eq!(s.num_clients(), 0);
    }

    #[test]
    fn display_panes_and_digit_select() {
        let mut s = state();
        s.host_msg(&HostMsg::SyncLayout(Layout {
            sx: 80,
            sy: 23,
            windows: vec![WindowLayout {
                idx: 2,
                name: "sh".into(),
                panes: vec![
                    PaneGeom {
                        id: 5,
                        sx: 40,
                        sy: 23,
                        xoff: 0,
                        yoff: 0,
                    },
                    PaneGeom {
                        id: 7,
                        sx: 39,
                        sy: 23,
                        xoff: 41,
                        yoff: 0,
                    },
                ],
                active_pane: 5,
            }],
            active_window: 2,
        }));
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let id = id.unwrap();
        let t0 = Instant::now();
        let out = type_at(&mut s, id, b"\x02q", t0);
        assert!(exec_cmds(&out).is_empty());
        assert_eq!(
            s.take_timers(),
            vec![Timer::Identify {
                viewer: id,
                generation: 1,
                after: Duration::from_millis(1000)
            }]
        );
        let shown = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(
            shown.contains("40x23") && shown.contains("39x23"),
            "{shown:?}"
        );
        let out = type_at(&mut s, id, b"1", t0 + Duration::from_millis(100));
        assert_eq!(
            exec_cmds(&out),
            vec![(
                1,
                vec![
                    "select-pane".to_string(),
                    "-t".to_string(),
                    "2.%7".to_string()
                ]
            )]
        );
        assert!(pane_keys(&out).is_empty());
        // The numbers are gone; a stale timer changes nothing.
        assert!(
            s.timer_fired(&Timer::Identify {
                viewer: id,
                generation: 1,
                after: Duration::ZERO
            })
            .is_empty()
        );
        // The timer clears the numbers when no key was pressed.
        type_at(&mut s, id, b"\x02q", t0 + Duration::from_millis(200));
        let timer = s.take_timers().pop().unwrap();
        let out = s.timer_fired(&timer);
        assert!(!viewer_bytes(&out, "v").is_empty());
        let out = type_at(&mut s, id, b"1", t0 + Duration::from_millis(300));
        assert_eq!(
            pane_keys(&out),
            vec![b'1' as u64],
            "digits are plain keys again"
        );
    }

    #[test]
    fn failed_command_shows_a_message() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        s.host_msg(&HostMsg::Status {
            left: "[default] ".into(),
            right: "".into(),
        });
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let id = id.unwrap();
        let out = s.host_msg(&HostMsg::FailedCmd {
            client_id: 1,
            cause: "can't find window: 9".into(),
        });
        let bytes = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(
            bytes.contains("\x1b[0;30;43mCan't find window: 9"),
            "{bytes:?}"
        );
        assert_eq!(status_row(&s, id), "Can't find window: 9");
        assert_eq!(
            s.take_timers(),
            vec![Timer::Message {
                viewer: id,
                generation: 1,
                after: Duration::from_millis(750)
            }]
        );
        assert!(
            s.host_msg(&HostMsg::FailedCmd {
                client_id: 42,
                cause: "nobody".into()
            })
            .is_empty()
        );

        let out = s.timer_fired(&Timer::Message {
            viewer: id,
            generation: 1,
            after: Duration::ZERO,
        });
        assert!(String::from_utf8_lossy(&viewer_bytes(&out, "v")).contains("[default] 0:bash*"));
        assert_eq!(status_row(&s, id), "[default] 0:bash*");

        // A key clears a message early and is still handled.
        s.host_msg(&HostMsg::FailedCmd {
            client_id: 1,
            cause: "oops".into(),
        });
        assert_eq!(status_row(&s, id), "Oops");
        let out = type_at(&mut s, id, b"x", Instant::now());
        assert_eq!(pane_keys(&out), vec![b'x' as u64]);
        assert_eq!(status_row(&s, id), "[default] 0:bash*");
        // display-time 0 keeps the message until a key.
        s.host_msg(&exec(&["set-option", "-g", "display-time", "0"]));
        s.take_timers();
        s.host_msg(&HostMsg::FailedCmd {
            client_id: 1,
            cause: "stay".into(),
        });
        assert!(s.take_timers().is_empty());
    }

    #[test]
    fn command_prompt_runs_on_the_server() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let id = id.unwrap();
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let out = type_at(&mut s, id, b"\x02:", t0);
        assert_eq!(status_row(&s, id), ":");
        assert!(String::from_utf8_lossy(&viewer_bytes(&out, "v")).contains("\x1b[0;30;43m:"));
        // Keys edit the prompt, nothing reaches the host.
        let out = type_at(&mut s, id, b"no-such-command", t0 + ms(100));
        assert!(host_msgs(&out).is_empty());
        assert_eq!(status_row(&s, id), ":no-such-command");
        let out = type_at(&mut s, id, b"\r", t0 + ms(200));
        assert!(host_msgs(&out).is_empty());
        assert_eq!(status_row(&s, id), "Unknown command: no-such-command");
        // A valid command goes to the host as argv.
        type_at(&mut s, id, b"\x02:", t0 + ms(300));
        let out = type_at(&mut s, id, b"rename-window renamed\r", t0 + ms(400));
        assert_eq!(
            exec_cmds(&out),
            vec![(1, vec!["rename-window".to_string(), "renamed".to_string()])]
        );
        assert!(s.viewers[&id].prompt.is_none());
        // Escape cancels; the prompt row goes back to the status line.
        type_at(&mut s, id, b"\x02:abc", t0 + ms(500));
        let (out, pending) = s.viewer_input_at(id, b"\x1b", t0 + ms(600));
        assert!(out.is_empty(), "a lone ESC is held for a sequence first");
        let out = s.flush_viewer(id, pending.unwrap());
        assert!(host_msgs(&out).is_empty());
        assert_eq!(status_row(&s, id), "0:bash*");
        // The window name is expanded into templates, and lists run in turn.
        let out = type_at(&mut s, id, b"\x02,", t0 + ms(700));
        assert!(!viewer_bytes(&out, "v").is_empty());
        assert_eq!(status_row(&s, id), "(rename-window) bash");
        let out = type_at(&mut s, id, b"-2\r", t0 + ms(800));
        assert_eq!(
            exec_cmds(&out),
            vec![(1, vec!["rename-window".to_string(), "bash-2".to_string()])]
        );
        type_at(&mut s, id, b"\x02:", t0 + ms(900));
        let out = type_at(&mut s, id, b"neww ; display hi\r", t0 + ms(1000));
        assert_eq!(
            exec_cmds(&out),
            vec![
                (1, vec!["new-window".to_string()]),
                (1, vec!["display-message".to_string(), "hi".to_string()]),
            ]
        );
        // confirm-before: y runs the command, anything else does not.
        type_at(&mut s, id, b"\x02&", t0 + ms(1100));
        assert_eq!(status_row(&s, id), "kill-window bash? (y/n)");
        let out = type_at(&mut s, id, b"n", t0 + ms(1200));
        assert!(host_msgs(&out).is_empty());
        type_at(&mut s, id, b"\x02&", t0 + ms(1300));
        let out = type_at(&mut s, id, b"y", t0 + ms(1400));
        assert_eq!(exec_cmds(&out), vec![(1, vec!["kill-window".to_string()])]);
    }

    #[test]
    fn copy_mode_is_mirrored() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 20, 5)], 0));
        let mut data = Vec::new();
        for i in 1..=10 {
            data.extend_from_slice(format!("line{i}\r\n").as_bytes());
        }
        s.host_msg(&HostMsg::PtyData { pane: 0, data });
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(20, 6));
        let id = id.unwrap();
        let out = s.host_msg(&HostMsg::SyncCopyMode {
            pane: 0,
            mode: Some(proto::CopyMode {
                backing: true,
                oy: 6,
                cx: 2,
                cy: 1,
                selection: Some(proto::Selection {
                    x: 0,
                    y_from_bottom: 10,
                    rect: false,
                }),
                input: None,
            }),
        });
        let text = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(text.contains("[6/6]"), "{text:?}");
        let last = s.viewers[&id].last.as_ref().unwrap();
        assert_eq!(last.rows_text()[0], "line1          [6/6]");
        assert_eq!(last.rows_text()[1], "line2");
        assert_eq!(
            last.get(0, 0).unwrap().attrs,
            render::Attrs::MODE,
            "selected from (0,0)"
        );
        assert_eq!(last.get(1, 2).unwrap().attrs, render::Attrs::MODE);
        assert_eq!(last.get(1, 3).unwrap().attrs, render::Attrs::default());
        assert_eq!(last.cursor, Some((1, 2)));
        // Keys in copy mode go to the host.
        let out = type_at(&mut s, id, b"q", Instant::now());
        assert_eq!(pane_keys(&out), vec![b'q' as u64]);
        // Leaving copy mode shows the live screen again.
        s.host_msg(&HostMsg::SyncCopyMode {
            pane: 0,
            mode: None,
        });
        let last = s.viewers[&id].last.as_ref().unwrap();
        assert_eq!(last.rows_text()[0], "line7");

        // Output written by the host (show-messages) is a scrollable buffer.
        s.host_msg(&HostMsg::WriteCopyMode {
            pane: 0,
            text: "msg one".into(),
        });
        s.host_msg(&HostMsg::WriteCopyMode {
            pane: 0,
            text: "msg two".into(),
        });
        let last = s.viewers[&id].last.as_ref().unwrap();
        assert_eq!(last.rows_text()[0], "msg one        [0/0]");
        assert_eq!(last.rows_text()[1], "msg two");
        s.host_msg(&HostMsg::SyncCopyMode {
            pane: 0,
            mode: Some(proto::CopyMode {
                backing: false,
                oy: 0,
                cx: 0,
                cy: 1,
                selection: None,
                input: None,
            }),
        });
        assert_eq!(s.viewers[&id].last.as_ref().unwrap().cursor, Some((1, 0)));
    }

    #[test]
    fn shrinking_panes_keep_history_and_clear_wipes_it() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 40)], 0));
        let mut data = b"\x1b[3J\x1b[H\x1b[2J$ seq 1 30\r\n".to_vec();
        for i in 1..=30 {
            data.extend_from_slice(format!("{i}\r\n").as_bytes());
        }
        data.extend_from_slice(b"$ ");
        s.host_msg(&HostMsg::PtyData { pane: 0, data });
        // A viewer whose terminal shrinks the pane: the top lines go to history.
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let id = id.unwrap();
        let rows = s.viewers[&id].last.as_ref().unwrap().rows_text();
        assert_eq!(rows[0], "9");
        assert_eq!(rows[22], "$");
        assert_eq!(s.viewers[&id].last.as_ref().unwrap().cursor, Some((22, 2)));
        assert_eq!(
            grid::history_len(&mut s.panes.get_mut(&0).unwrap().parser),
            9
        );
        // `clear` (3J H 2J): 3J empties the history, then 2J scrolls the
        // 23 used screen lines into it, as tmux does.
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"\x1b[3J\x1b[H\x1b[2J$ ".to_vec(),
        });
        assert_eq!(
            grid::history_len(&mut s.panes.get_mut(&0).unwrap().parser),
            23
        );
        let rows = s.viewers[&id].last.as_ref().unwrap().rows_text();
        assert_eq!(rows[0], "$");
        assert!(rows[1..23].iter().all(String::is_empty));
        // 3J alone wipes it.
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"\x1b[3J".to_vec(),
        });
        assert_eq!(
            grid::history_len(&mut s.panes.get_mut(&0).unwrap().parser),
            0
        );
        // `clear` under TERM=screen: H then J on the top row scrolls the
        // used lines ("$ ") into history; J lower down does not.
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"\x1b[H\x1b[J$ ".to_vec(),
        });
        assert_eq!(
            grid::history_len(&mut s.panes.get_mut(&0).unwrap().parser),
            1
        );
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"\r\nmore\x1b[J".to_vec(),
        });
        assert_eq!(
            grid::history_len(&mut s.panes.get_mut(&0).unwrap().parser),
            1
        );
        assert_eq!(s.viewers[&id].last.as_ref().unwrap().rows_text()[1], "more");
    }

    #[test]
    fn snapshot_restores_panes() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 10, 3)], 0));
        s.host_msg(&HostMsg::PtyData {
            pane: 0,
            data: b"stale".to_vec(),
        });
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(10, 4));
        let d = 0x0808;
        let out = s.host_msg(&HostMsg::Snapshot(vec![proto::PaneSnapshot {
            id: 0,
            mode: 1,
            grid: proto::SnapshotGrid {
                cx: 3,
                cy: 1,
                lines: vec![
                    proto::SnapshotLine {
                        text: "gone".into(),
                        cells: vec![d; 4],
                    },
                    proto::SnapshotLine {
                        text: "fresh".into(),
                        cells: vec![0x0001_0801, d, d, d, d],
                    },
                    proto::SnapshotLine {
                        text: "two".into(),
                        cells: vec![d; 3],
                    },
                    proto::SnapshotLine {
                        text: "".into(),
                        cells: vec![],
                    },
                ],
            },
            saved: None,
        }]));
        let text = String::from_utf8_lossy(&viewer_bytes(&out, "v")).into_owned();
        assert!(text.contains("resh") && !text.contains("stale"), "{text:?}");
        let last = s.viewers[&id.unwrap()].last.as_ref().unwrap();
        assert_eq!(last.rows_text()[..3], ["fresh", "two", ""]);
        assert!(last.get(0, 0).unwrap().attrs.bold);
        assert_eq!(last.cursor, Some((1, 3)));
        // Unknown panes are skipped.
        assert!(
            s.host_msg(&HostMsg::Snapshot(vec![proto::PaneSnapshot {
                id: 9,
                mode: 1,
                grid: proto::SnapshotGrid {
                    cx: 0,
                    cy: 0,
                    lines: vec![]
                },
                saved: None,
            }]))
            .is_empty()
        );
    }

    #[test]
    fn reconnect_hands_over_the_host() {
        let mut s = state();
        s.host_msg(&layout(&[(0, 80, 23)], 0));
        let (id, _) = s.attach_viewer("v", Access::ReadWrite, "1.1.1.1", size(80, 24));
        let out = s.host_adopted("host2");
        assert!(
            out.iter()
                .any(|o| o.to == HOST && o.payload == Payload::Close)
        );
        assert_eq!(status_row(&s, id.unwrap()), RECONNECTED_MSG);
        assert!(s.take_reconnected());
        assert!(!s.take_reconnected());
        // READY from the new host gets the current size again.
        let out = s.host_ready();
        assert_eq!(out[0].to, "host2");
        let mut d = Decoder::new();
        if let Payload::Data(b) = &out[0].payload {
            d.feed(b);
        }
        assert_eq!(
            d.next_value().unwrap().unwrap(),
            Value::Array(vec![Value::Int(2), Value::Int(80), Value::Int(23)])
        );
        // Keys now go to the new host.
        let out = type_at(&mut s, id.unwrap(), b"k", Instant::now());
        assert!(out.iter().any(|o| o.to == "host2"));
        // A fresh session has nothing to resend at READY.
        assert!(state().host_ready().is_empty());
    }

    #[test]
    fn ending_tells_and_closes_viewers() {
        let mut s = state();
        s.attach_viewer("a", Access::ReadWrite, "1.1.1.1", size(80, 24));
        s.attach_viewer("b", Access::ReadOnly, "2.2.2.2", size(80, 24));
        let out = s.end();
        assert_eq!(out.len(), 4);
        assert_eq!(viewer_bytes(&out, "a"), SESSION_ENDED);
        assert!(
            out.iter()
                .any(|o| o.to == "b" && o.payload == Payload::Close)
        );
        assert_eq!(s.num_clients(), 0);
        assert!(s.end().is_empty());

        let (id, out) = s.attach_viewer("late", Access::ReadWrite, "3.3.3.3", size(80, 24));
        assert_eq!(id, None);
        assert_eq!(viewer_bytes(&out, "late"), SESSION_ENDED);
        assert!(
            host_msgs(&out).is_empty(),
            "the host is not told about viewers that never joined"
        );
    }

    #[test]
    fn set_option_argv_parsing() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            set_option_args(&args(&[
                "set-option",
                "-g",
                "-q",
                "tmate-authorized-keys",
                "p"
            ])),
            Some(("tmate-authorized-keys", "p"))
        );
        assert_eq!(
            set_option_args(&args(&["set", "-t", "0", "x", "y"])),
            Some(("x", "y"))
        );
        assert_eq!(
            set_option_args(&args(&["set-option", "-u", "x"])),
            Some(("x", ""))
        );
        assert_eq!(set_option_args(&args(&["display", "x"])), None);
        assert_eq!(set_option_args(&args(&["set-option"])), None);
        assert_eq!(capitalise("can't find"), "Can't find");
        assert_eq!(capitalise(""), "");
        let v = FormatValues {
            window_name: "vim".into(),
            window_idx: 3,
            pane_idx: 1,
        };
        assert_eq!(
            expand_format("kill-window #W? (y/n) #I.#P ## #x #", &v),
            "kill-window vim? (y/n) 3.1 # #x #"
        );
    }

    #[test]
    fn adopted_host_replaces_the_old_connection_on_the_same_hub() {
        let hub = Hub::new(false, false);
        let (old_host, mut old_rx) = Peer::new();
        hub.set_host(old_host);
        let (new_host, _new_rx) = Peer::new();
        hub.host_adopted(new_host.clone());
        assert_eq!(
            old_rx.try_recv(),
            Some(Payload::Close),
            "the old host connection is closed"
        );
        assert!(hub.take_reconnected());
        assert!(!hub.take_reconnected(), "reported once");
        hub.send_host(Bytes::from_static(b"x"));
        assert!(!hub.is_ended());
        hub.end();
        assert!(hub.is_ended());
    }

    #[tokio::test]
    async fn peers_that_do_not_drain_are_cut_off() {
        let (peer, mut rx) = Peer::new();
        let chunk = Bytes::from(vec![0u8; MAX_QUEUED / 4]);
        for _ in 0..4 {
            peer.send(Payload::Data(chunk.clone()));
        }
        assert!(!peer.is_kicked(), "exactly the limit is still fine");
        peer.send(Payload::Data(Bytes::from_static(b"one more byte")));
        assert!(peer.is_kicked());
        peer.send(Payload::Data(Bytes::from_static(b"dropped")));
        let mut got = Vec::new();
        while let Some(p) = rx.try_recv() {
            got.push(p);
        }
        assert_eq!(got.len(), 5);
        assert_eq!(got[4], Payload::Close);
        // Draining releases the counter.
        let (peer, mut rx) = Peer::new();
        for _ in 0..40 {
            peer.send(Payload::Data(chunk.clone()));
            assert!(rx.recv().await.is_some());
        }
        assert!(!peer.is_kicked());
    }

    struct FakeSink {
        /// What the sink took: "data <len>", "eof", "close".
        log: Arc<std::sync::Mutex<Vec<String>>>,
        /// Nothing completes: the session is window-blocked.
        stuck: bool,
    }

    impl FakeSink {
        fn new(stuck: bool) -> (FakeSink, Arc<std::sync::Mutex<Vec<String>>>) {
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                FakeSink {
                    log: log.clone(),
                    stuck,
                },
                log,
            )
        }

        async fn took(&self, what: String) {
            if self.stuck {
                std::future::pending::<()>().await;
            }
            self.log.lock().unwrap().push(what);
        }
    }

    impl ChannelSink for FakeSink {
        async fn data(&self, data: Bytes) -> Result<(), ()> {
            self.took(format!("data {}", data.len())).await;
            Ok(())
        }
        async fn eof(&self) {
            self.took("eof".into()).await;
        }
        async fn close(&self) {
            self.took("close".into()).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_kicked_peer_has_its_connection_cut_at_once() {
        let (peer, rx) = Peer::new();
        let (sink, _log) = FakeSink::new(true);
        let cut = Cut::new();
        let writer = tokio::spawn(write_peer(rx, sink, cut.clone()));
        let chunk = Bytes::from(vec![0u8; MAX_QUEUED / 2]);
        // The writer takes the first chunk and parks in the stuck send;
        // the next two fill the queue to exactly the limit.
        peer.send(Payload::Data(chunk.clone()));
        tokio::task::yield_now().await;
        peer.send(Payload::Data(chunk.clone()));
        peer.send(Payload::Data(chunk.clone()));
        assert!(!peer.is_kicked());
        assert!(!cut.is_cut(), "a slow peer is tolerated up to the limit");
        peer.send(Payload::Data(chunk));
        assert!(peer.is_kicked());
        tokio::time::timeout(Duration::from_millis(10), writer)
            .await
            .expect("the writer parked in a send is woken")
            .unwrap();
        assert!(cut.is_cut());
    }

    #[tokio::test(start_paused = true)]
    async fn a_close_the_peer_does_not_take_cuts_after_the_grace() {
        let (peer, rx) = Peer::new();
        let (sink, _log) = FakeSink::new(true);
        let cut = Cut::new();
        let writer = tokio::spawn(write_peer(rx, sink, cut.clone()));
        peer.send(Payload::Close);
        tokio::time::sleep(CLOSE_GRACE - Duration::from_secs(1)).await;
        assert!(!cut.is_cut());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cut.is_cut());
        writer.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_channel_is_followed_by_a_cut() {
        let (peer, rx) = Peer::new();
        let (sink, log) = FakeSink::new(false);
        let cut = Cut::new();
        let writer = tokio::spawn(write_peer(rx, sink, cut.clone()));
        peer.send(Payload::Data(Bytes::from_static(b"bye")));
        peer.send(Payload::Close);
        writer.await.unwrap();
        assert_eq!(log.lock().unwrap().as_slice(), ["data 3", "eof", "close"]);
        assert!(!cut.is_cut(), "the client gets a moment to close");
        tokio::time::sleep(CLOSE_GRACE + Duration::from_secs(1)).await;
        assert!(cut.is_cut());
    }

    fn pty(pane: i64, data: &[u8]) -> HostMsg {
        HostMsg::PtyData {
            pane,
            data: data.to_vec(),
        }
    }

    #[test]
    fn with_a_backend_presence_is_its_business() {
        let mut s = state();
        s.set_backend(true);
        let (a, out) = s.attach_viewer("a", Access::ReadWrite, "10.0.0.1", size(80, 24));
        assert!(notices(&out).is_empty());
        assert_eq!(set_env_of(&out, "tmate_num_clients"), None);
        assert_eq!(resize_of(&out), Some((80, 23)), "the size rule still runs");
        let out = s.detach_viewer(a.unwrap());
        assert!(notices(&out).is_empty());
        assert_eq!(resize_of(&out), Some((-1, -1)));
    }

    #[test]
    fn backend_size_joins_the_size_rule() {
        let mut s = state();
        s.set_backend(true);
        // A web client alone sizes the pane.
        let out = s.backend_resize(100, 30);
        assert_eq!(resize_of(&out), Some((100, 30)));
        // Each dimension is the minimum over web and ssh clients.
        let (a, out) = s.attach_viewer("a", Access::ReadWrite, "10.0.0.1", size(120, 20));
        assert_eq!(resize_of(&out), Some((100, 19)));
        let out = s.backend_resize(90, 50);
        assert_eq!(resize_of(&out), Some((90, 19)));
        // -1 from the backend means no web client; a huge size is clamped.
        let out = s.backend_resize(-1, -1);
        assert_eq!(resize_of(&out), Some((120, 19)));
        let out = s.detach_viewer(a.unwrap());
        assert_eq!(resize_of(&out), Some((-1, -1)));
        let out = s.backend_resize(5000, 5000);
        assert_eq!(resize_of(&out), Some((500, 500)));
        assert!(
            s.backend_resize(5000, 5000).is_empty(),
            "unchanged sizes are not repeated"
        );
    }

    #[test]
    fn snapshot_lists_panes_in_window_order() {
        let mut s = state();
        s.host_msg(&layout(&[(7, 10, 2), (3, 10, 2)], 3));
        s.host_msg(&pty(7, b"seven"));
        s.host_msg(&pty(3, b"a\r\nb\r\nc"));
        let snap = s.snapshot(300);
        let ids: Vec<i64> = snap.iter().map(|p| p.id).collect();
        assert_eq!(ids, [7, 3]);
        assert_eq!(snap[0].lines[0].text, "seven");
        assert_eq!((snap[0].cx, snap[0].cy), (5, 0));
        let texts: Vec<&str> = snap[1].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["a", "b", "c"], "history is included");
        let snap = s.snapshot(0);
        let texts: Vec<&str> = snap[1].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["b", "c"], "history limited by the request");
        let mut empty = state();
        assert!(empty.snapshot(300).is_empty(), "no layout, no panes");
    }

    #[test]
    fn named_session_options_warn_once_without_a_backend() {
        let mut s = state();
        let set = |name: &str| {
            HostMsg::ExecCmd(
                ["set-option", "-g", name, "demo"]
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            )
        };
        let out = s.host_msg(&set("tmate-session-name"));
        assert_eq!(notices(&out), vec![NAMED_SESSIONS_UNSUPPORTED_MSG]);
        assert!(s.host_msg(&set("tmate-api-key")).is_empty(), "warned once");
        assert!(s.host_msg(&set("status-left")).is_empty());

        let mut s = state();
        s.set_backend(true);
        assert!(
            s.host_msg(&set("tmate-session-name-ro")).is_empty(),
            "the backend names sessions"
        );
    }
}
