//! Differential replay: an identical, recorded host stream (a layout, PTY
//! output, an optional mid-stream resize via a second SYNC_LAYOUT, then a
//! SYNC_COPY_MODE) is fed to both the Rust server and the reference C
//! server, a viewer attaches to each, and the two viewer screens — the
//! copy-mode `[oy/hsize]` indicator included — must match exactly.
//!
//! This pins the pane-history semantics (`clear`-style erase sequences and
//! pane resizes) that the flaky `copy_mode_matches_reference` parity
//! scenario exercises: both servers see the *same* bytes here, so any
//! difference is a real semantic difference in our port of tmux 2.2.
//!
//! Skipped unless `TMATE_REF_ADDR`/`TMATE_REF_FINGERPRINT` point at a
//! reference server (as `scripts/parity.sh` sets up), like `tests/parity.rs`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use russh::client;
use support::{NewServer, Target, Viewer, reference_target};

/// One step of a recorded host stream.
#[derive(Clone)]
enum Step {
    /// A SYNC_LAYOUT with a single `sx`×`sy` pane (id 0), named `name`.
    Layout {
        sx: i64,
        sy: i64,
        name: &'static str,
    },
    /// PTY_DATA for pane 0.
    Pty(Vec<u8>),
}

fn layout(sx: i64, sy: i64) -> Step {
    Step::Layout { sx, sy, name: "sh" }
}
fn pty(bytes: &[u8]) -> Step {
    Step::Pty(bytes.to_vec())
}

/// msgpack helpers (only the shapes the recorded streams need).
mod mp {
    pub fn arr(n: usize, out: &mut Vec<u8>) {
        assert!(n < 16);
        out.push(0x90 | n as u8);
    }
    pub fn int(v: i64, out: &mut Vec<u8>) {
        if (0..=0x7f).contains(&v) {
            out.push(v as u8);
        } else if (-32..0).contains(&v) {
            out.push(v as i8 as u8);
        } else if (0..=0xffff).contains(&v) {
            out.push(0xcd);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        } else {
            out.push(0xd3);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    pub fn strs(s: &str, out: &mut Vec<u8>) {
        bin(s.as_bytes(), out);
    }
    pub fn bin(b: &[u8], out: &mut Vec<u8>) {
        out.push(0xdb);
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
}

fn header_and_ready() -> Vec<u8> {
    let mut out = Vec::new();
    mp::arr(3, &mut out);
    mp::int(0, &mut out); // HEADER
    mp::int(6, &mut out); // protocol 6
    mp::strs("2.4.0", &mut out);
    mp::arr(1, &mut out);
    mp::int(9, &mut out); // READY
    out
}

fn encode_step(step: &Step) -> Vec<u8> {
    let mut out = Vec::new();
    match step {
        Step::Layout { sx, sy, name } => {
            // [SYNC_LAYOUT, sx, sy, [[idx, name, [[id, sx, sy, 0, 0]], active_pane]], active_win]
            mp::arr(5, &mut out);
            mp::int(1, &mut out);
            mp::int(*sx, &mut out);
            mp::int(*sy, &mut out);
            mp::arr(1, &mut out); // windows
            mp::arr(4, &mut out); // window
            mp::int(0, &mut out); // idx
            mp::strs(name, &mut out);
            mp::arr(1, &mut out); // panes
            mp::arr(5, &mut out); // pane
            mp::int(0, &mut out); // id
            mp::int(*sx, &mut out);
            mp::int(*sy, &mut out);
            mp::int(0, &mut out); // xoff
            mp::int(0, &mut out); // yoff
            mp::int(0, &mut out); // active_pane
            mp::int(0, &mut out); // active_win
        }
        Step::Pty(bytes) => {
            mp::arr(3, &mut out);
            mp::int(2, &mut out); // PTY_DATA
            mp::int(0, &mut out); // pane 0
            mp::bin(bytes, &mut out);
        }
    }
    out
}

/// [SYNC_COPY_MODE, pane, [backing, oy, cx, cy, [], []]] for the backing pane.
fn sync_copy_mode(oy: i64, cx: i64, cy: i64) -> Vec<u8> {
    let mut out = Vec::new();
    mp::arr(3, &mut out);
    mp::int(6, &mut out); // SYNC_COPY_MODE
    mp::int(0, &mut out); // pane 0
    mp::arr(6, &mut out);
    mp::int(1, &mut out); // backing = pane
    mp::int(oy, &mut out);
    mp::int(cx, &mut out);
    mp::int(cy, &mut out);
    mp::arr(0, &mut out); // no selection
    mp::arr(0, &mut out); // no input
    out
}

struct Accept;
impl client::Handler for Accept {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A host that speaks raw bytes and can recover the session token the
/// server hands back via `tmate_ssh` SET_ENV.
struct FakeHost {
    // Keeps the connection open: dropping the handle disconnects the session
    // before the server can flush the token back.
    _session: client::Handle<Accept>,
    channel: russh::ChannelWriteHalf<client::Msg>,
    received: Arc<tokio::sync::Mutex<Vec<u8>>>,
}

impl FakeHost {
    async fn connect(target: &Target) -> FakeHost {
        let mut session = client::connect(
            Arc::new(client::Config::default()),
            (target.host.as_str(), target.port),
            Accept,
        )
        .await
        .expect("connect");
        assert!(matches!(
            session.authenticate_none("tmate").await.expect("auth"),
            client::AuthResult::Success
        ));
        let channel = session.channel_open_session().await.expect("channel");
        channel
            .request_subsystem(true, "tmate")
            .await
            .expect("subsystem");
        let (mut reader, channel) = channel.split();
        let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink = received.clone();
        tokio::spawn(async move {
            while let Some(msg) = reader.wait().await {
                if let russh::ChannelMsg::Data { data } = msg {
                    sink.lock().await.extend_from_slice(&data);
                }
            }
        });
        FakeHost {
            _session: session,
            channel,
            received,
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.channel
            .data_bytes(bytes::Bytes::copy_from_slice(bytes))
            .await
            .expect("send");
    }

    async fn token(&self) -> Option<String> {
        extract_token(&self.received.lock().await)
    }

    /// Resends `opening` until the server publishes the ssh token. The old C
    /// server drops channel data sent during its first second or so (while it
    /// sets up the jail and loads its config), so a single send races the
    /// daemon's startup; resending the HEADER/READY/layout is idempotent.
    async fn handshake(&mut self, opening: &[u8]) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            self.send(opening).await;
            for _ in 0..10 {
                if let Some(t) = self.token().await {
                    return t;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(std::time::Instant::now() < deadline, "no token from server");
        }
    }
}

/// Finds the read-write token in the bytes the server sent: it appears in a
/// `tmate_ssh` SET_ENV value shaped `ssh -pPORT <token>@host`. The read-only
/// one (`ro-…`) is skipped.
fn extract_token(buf: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    for (i, _) in text.match_indices("ssh -p") {
        let rest = &text[i + "ssh -p".len()..];
        // skip the port digits and the single space before the token
        let after_port = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        let after_port = after_port.strip_prefix(' ')?;
        if let Some(at) = after_port.find('@') {
            let token = &after_port[..at];
            if !token.is_empty()
                && !token.starts_with("ro-")
                && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Feeds `stream` to `target`, attaches an 80×24 viewer, enters copy mode at
/// `(oy, cx, cy)`, and returns the viewer's pane rows (status row dropped).
async fn replay_on(target: &Target, stream: &[Step], cm: (i64, i64, i64)) -> Vec<String> {
    let mut host = FakeHost::connect(target).await;
    // HEADER, READY and the first step (a SYNC_LAYOUT, which creates the
    // server-side session) go in one burst: the server-side tmux exits the
    // moment its loop sees no session, so the layout must be processed before
    // the first exit check. `handshake` resends this burst until the token
    // comes back, since the old server drops data during its startup.
    let mut opening = header_and_ready();
    opening.extend(encode_step(&stream[0]));
    let token = host.handshake(&opening).await;

    // The rest of the stream, in order.
    for step in &stream[1..] {
        host.send(&encode_step(step)).await;
        // A small gap so layout/PTY ordering is preserved on the wire.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Let the stream settle before a viewer reads it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The viewer must match the final pane size (one extra row for the status
    // line), so neither server resizes the pane when it attaches.
    let (sx, sy) = stream
        .iter()
        .rev()
        .find_map(|s| match s {
            Step::Layout { sx, sy, .. } => Some((*sx as u16, *sy as u16)),
            _ => None,
        })
        .unwrap();
    let viewer = Viewer::connect(target, &token, sx, sy + 1).await.unwrap();
    // Wait until the viewer has the pane (some content on screen); don't
    // panic on timeout, so the fuzzer can compare whatever rendered.
    poll(&viewer, Duration::from_secs(5), |rows| {
        rows.iter().any(|r| !r.is_empty())
    })
    .await;

    host.send(&sync_copy_mode(cm.0, cm.1, cm.2)).await;
    let rows = poll(&viewer, Duration::from_secs(5), |rows| {
        rows.iter().any(|r| r.contains('['))
    })
    .await;
    viewer.close().await;
    rows
}

/// Polls the viewer's pane rows until `pred` holds or the timeout passes,
/// returning whatever is on screen either way (no panic).
async fn poll(viewer: &Viewer, timeout: Duration, pred: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let rows = viewer.pane_rows().await;
        if pred(&rows) || std::time::Instant::now() >= deadline {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A named stream plus the copy-mode `(oy, cx, cy)` to enter it at.
type NamedStream = (String, Vec<Step>, (i64, i64, i64));

/// The recorded/hand-crafted streams. Each enters copy mode at the end.
fn streams() -> Vec<NamedStream> {
    // The seq 1 40 tail the real scenario produces.
    let seq_tail = || {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(b"seq 1 40\r\n");
        for i in 1..=40 {
            v.extend_from_slice(format!("{i}\r\n").as_bytes());
        }
        v.extend_from_slice(b"$ ");
        v
    };

    let mut out = Vec::new();

    // Recorded "run 1": one echoed prompt line before the first clear.
    out.push((
        "recorded_run1",
        vec![
            layout(200, 59),
            pty(b"$ clear\r\n\x1b[H\x1b[J$ "),
            layout(80, 23),
            pty(b"\r\x1b[K$ "),
            pty(b"clear\r\n\x1b[H\x1b[J$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    // Recorded "run 2": the command echoes on its own line first (two used
    // lines at 200×59).
    out.push((
        "recorded_run2",
        vec![
            layout(200, 59),
            pty(b"clear\r\n$ clear\r\n\x1b[H\x1b[J$ "),
            layout(80, 23),
            pty(b"\r\x1b[K$ "),
            pty(b"clear\r\n\x1b[H\x1b[J$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    // A bash-style SIGWINCH redraw that writes trailing spaces instead of
    // using \033[K, then a clear: tests "blank but written" line handling.
    out.push((
        "spaces_then_clear",
        vec![
            layout(80, 23),
            pty(b"$ echo hi\r\nhi\r\n$ "),
            // redraw: CR, overwrite prompt + trailing spaces, CR again
            pty(b"\r$ \r"),
            pty(b"\x1b[H\x1b[J$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    // CSI 2 J (whole screen) with the cursor low on the screen.
    out.push((
        "csi_2j_cursor_low",
        vec![
            layout(80, 23),
            pty(b"$ one\r\ntwo\r\nthree"),
            pty(b"\x1b[2J"),
            pty(b"\x1b[H$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    // CSI J (to end) with the cursor on the top row but not column 0.
    out.push((
        "csi_j_top_row_midcol",
        vec![
            layout(80, 23),
            pty(b"$ aaa\r\nbbb\r\nccc\x1b[H\x1b[5C\x1b[J$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    // Grow resize after a shrink: lines must be pulled back from history.
    out.push((
        "shrink_then_grow",
        vec![
            layout(80, 40),
            pty(b"$ seq 1 60\r\n"),
            pty(&{
                let mut v = Vec::new();
                for i in 1..=60 {
                    v.extend_from_slice(format!("{i}\r\n").as_bytes());
                }
                v.extend_from_slice(b"$ ");
                v
            }),
            layout(80, 10),
            layout(80, 50),
            pty(b"echo done\r\ndone\r\n$ "),
        ],
        (0, 2, 9),
    ));

    // A blank-but-written last line then a whole-screen clear: tmux counts it
    // by cellsize, so it scrolls two lines into history, not one.
    out.push((
        "trailing_blank_clear",
        vec![layout(24, 6), pty(b"a\r\n   \x1b[H\x1b[2J$ ")],
        (0, 2, 0),
    ));

    // Linefeeds at the bottom row (pure scrolling) after a width change.
    out.push((
        "scroll_at_bottom_after_resize",
        vec![
            layout(200, 59),
            pty(b"$ "),
            layout(80, 23),
            pty(b"\r\x1b[K$ "),
            pty(&seq_tail()),
        ],
        (0, 2, 22),
    ));

    out.into_iter()
        .map(|(n, s, c): (&str, Vec<Step>, (i64, i64, i64))| (n.to_string(), s, c))
        .collect()
}

/// A deterministic LCG, so a failing fuzz stream can be reproduced.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Builds `count` randomized streams: a small pane that is written to,
/// cleared, scrolled and resized in height, exercising the history
/// semantics. Width is held constant (no reflow), matching the port.
fn fuzz_streams(count: usize) -> Vec<NamedStream> {
    let sx: i64 = 24;
    let mut streams = Vec::new();
    for seed in 0..count {
        let mut rng = Rng(seed as u64 * 2_654_435_761 + 12345);
        let mut sy: i64 = 4 + rng.below(6) as i64;
        let mut steps = vec![layout(sx, sy)];
        let mut pending: Vec<u8> = Vec::new();
        let ops = 6 + rng.below(10);
        for _ in 0..ops {
            match rng.below(8) {
                0 => pending.extend_from_slice(b"$ "),
                1 => {
                    // a short line then newline (may scroll at the bottom)
                    let n = rng.below(5) + 1;
                    for _ in 0..n {
                        pending.push(b'a' + rng.below(20) as u8);
                    }
                    pending.extend_from_slice(b"\r\n");
                }
                2 => pending.extend_from_slice(b"\x1b[H\x1b[J"), // screen's `clear`
                3 => pending.extend_from_slice(b"\x1b[2J"),
                4 => pending.extend_from_slice(b"\x1b[3J"),
                5 => {
                    // bash-like redraw: CR, clear-to-eol, prompt
                    pending.extend_from_slice(b"\r\x1b[K$ ");
                }
                6 => {
                    // a line with trailing spaces (cellsize > trimmed length)
                    pending.extend_from_slice(b"xy   ");
                    pending.extend_from_slice(b"\r\n");
                }
                _ => {
                    // flush pending, then a height resize (+ a redraw after)
                    steps.push(pty(&std::mem::take(&mut pending)));
                    sy = 4 + rng.below(8) as i64;
                    steps.push(Step::Layout { sx, sy, name: "sh" });
                    pending.extend_from_slice(b"\r\x1b[K$ ");
                }
            }
        }
        if !pending.is_empty() {
            steps.push(pty(&pending));
        }
        // End at the current size.
        steps.push(Step::Layout { sx, sy, name: "sh" });
        streams.push((format!("fuzz_{seed}"), steps, (0, 0, 0)));
    }
    streams
}

#[tokio::test]
async fn replay_matches_reference() {
    let Some(reference) = reference_target() else {
        eprintln!("skipping: needs TMATE_REF_ADDR/TMATE_REF_FINGERPRINT");
        return;
    };
    let server = NewServer::start();

    let mut all = streams();
    all.extend(fuzz_streams(
        std::env::var("REPLAY_FUZZ")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    ));

    let mut failures = Vec::new();
    for (name, stream, cm) in all {
        let ours = replay_on(&server.target, &stream, cm).await;
        let theirs = replay_on(&reference, &stream, cm).await;
        if ours != theirs {
            failures.push(format!(
                "stream `{name}` differs:\n  ours:   {ours:?}\n  theirs: {theirs:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
