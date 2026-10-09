//! Shared fixtures for the live tests: a server under test, a real tmate
//! 2.4.0 host driven through its local socket, and a scripted SSH viewer
//! whose terminal is emulated with `vt100` so screens can be compared.
//!
//! The same fixtures drive the Rust server and the old C server (reached via
//! `TMATE_REF_ADDR` + `TMATE_REF_FINGERPRINT`), which is what the parity
//! tests rely on.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client;
use russh::{ChannelMsg, Pty};
use tokio::sync::Mutex;

pub fn tmate_binary() -> Option<PathBuf> {
    let out = Command::new("which").arg("tmate").output().ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Where a server can be reached and how the tmate client should trust it.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub ed25519_fingerprint: String,
    /// Whether the server sets `tmate_num_clients` and sends join/leave
    /// notices. The old C server only did so through its Elixir backend;
    /// standalone it did neither, while action-tmate relies on both.
    pub has_backend_features: bool,
}

/// The Rust server, started on a free port with a temporary key directory.
pub struct NewServer {
    child: Child,
    pub target: Target,
    _dir: tempfile::TempDir,
}

impl NewServer {
    pub fn start() -> Self {
        Self::start_with_args(&[])
    }

    pub fn start_with_args(extra: &[&str]) -> Self {
        let mut last_log = String::new();
        // Picking a free port and binding it are two steps; a parallel test
        // can grab the port in between, so retry on a failed start.
        for _ in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let port = free_port();
            let mut child = Command::new(env!("CARGO_BIN_EXE_tmate-server-rs"))
                .arg("--listen")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--host")
                .arg("127.0.0.1")
                .arg("--keys-dir")
                .arg(dir.path().join("keys"))
                .args(extra)
                .env("RUST_LOG", "info")
                .stderr(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn server");
            let stderr = child.stderr.take().unwrap();
            match read_until_listening(stderr) {
                Ok(fingerprint) => {
                    wait_for_port(port);
                    return NewServer {
                        child,
                        target: Target {
                            host: "127.0.0.1".into(),
                            port,
                            ed25519_fingerprint: fingerprint,
                            has_backend_features: true,
                        },
                        _dir: dir,
                    };
                }
                Err(log) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    last_log = log;
                }
            }
        }
        panic!("server failed to start repeatedly; last log:\n{last_log}");
    }
}

impl Drop for NewServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads the server's startup log until it is listening. Returns the host
/// key fingerprint, or the log so far if the server gave up (for example a
/// port race with another test).
fn read_until_listening(stderr: std::process::ChildStderr) -> Result<String, String> {
    use std::io::BufRead;
    let mut lines = std::io::BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    let mut fingerprint = None;
    for line in lines.by_ref() {
        let line = line.unwrap();
        if let Some(pos) = line.find("SHA256:") {
            fingerprint = Some(
                line[pos..]
                    .chars()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == ':'
                    })
                    .collect::<String>(),
            );
        }
        if line.contains("accepting connections")
            && let Some(fp) = fingerprint
        {
            // Keep draining stderr so the server never blocks on a full pipe;
            // echo it so a failing test shows the server's side.
            std::thread::spawn(move || {
                for line in lines.map_while(Result::ok) {
                    eprintln!("[server] {line}");
                }
            });
            return Ok(fp);
        }
        seen.push(line);
    }
    Err(seen.join("\n"))
}

/// The reference (old C) server, if the environment points at one.
pub fn reference_target() -> Option<Target> {
    let addr = std::env::var("TMATE_REF_ADDR").ok()?;
    let fp = std::env::var("TMATE_REF_FINGERPRINT").ok()?;
    let (host, port) = addr.rsplit_once(':')?;
    Some(Target {
        host: host.to_string(),
        port: port.parse().ok()?,
        ed25519_fingerprint: fp,
        has_backend_features: std::env::var("TMATE_REF_HAS_BACKEND")
            .map(|v| v == "1")
            .unwrap_or(false),
    })
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {port} never opened");
}

/// A real tmate 2.4.0 client acting as the host, controlled through its
/// local socket exactly as action-tmate does.
pub struct Host {
    tmate: PathBuf,
    conf: PathBuf,
    sock: PathBuf,
    attached: Option<Child>,
    _dir: tempfile::TempDir,
}

impl Host {
    pub fn start(target: &Target) -> Self {
        Self::start_with_conf(target, "")
    }

    /// `extra_conf` is appended to the generated tmate.conf (e.g. `set -g tmate-authorized-keys ...`).
    pub fn start_with_conf(target: &Target, extra_conf: &str) -> Self {
        let tmate = tmate_binary().expect("tmate binary in PATH");
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("tmate.conf");
        std::fs::write(
            &conf,
            format!(
                "set -g tmate-server-host {}\nset -g tmate-server-port {}\nset -g tmate-server-ed25519-fingerprint \"{}\"\nset -g status-right \"\"\n{extra_conf}\n",
                target.host, target.port, target.ed25519_fingerprint
            ),
        )
        .unwrap();
        // Unix sockets have a ~100 byte path limit; keep it short.
        let sock = PathBuf::from(format!(
            "/tmp/tmate-t-{}.sock",
            std::process::id() ^ free_port() as u32
        ));
        let mut host = Host {
            tmate,
            conf,
            sock,
            attached: None,
            _dir: dir,
        };
        // tmate only keeps a message log and status text for attached clients,
        // and notices that arrive while nobody is attached are lost, so the
        // session is created by a client that stays attached in a pty.
        let attached = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/attach.py"
            ))
            .arg(&host.tmate)
            .arg("-f")
            .arg(&host.conf)
            .arg("-S")
            .arg(&host.sock)
            .args(["new-session", "-x", "80", "-y", "24", "/bin/sh"])
            .env("TERM", "xterm-256color")
            .env("PS1", "$ ")
            .env("ENV", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start host client");
        host.attached = Some(attached);
        let deadline = Instant::now() + Duration::from_secs(10);
        while self_cmd(&host)
            .args(["display", "-p", "ok"])
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            assert!(Instant::now() < deadline, "tmate session never came up");
            std::thread::sleep(Duration::from_millis(50));
        }
        host
    }

    /// Does what a person does after `tmate` starts: waits for the server,
    /// dismisses tmate's own notice screen and redraws the prompt so the pane
    /// has output the server has seen. Returns false if the server never
    /// answered READY.
    pub fn prepare(&self) -> bool {
        if !self.wait_ready(Duration::from_secs(15)) {
            return false;
        }
        // The startup tips are shown in a copy-mode window; `q` leaves it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.display("#{pane_in_mode}") != "1" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.send_keys(&["q"]);
        while self.display("#{pane_in_mode}") != "0" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.clear();
        // tmate sends its status text once, when it changes. The first
        // STATUS is emitted before the daemon connection is up and is lost,
        // so without a change the server never learns status-left and the
        // status row depends on timing. Setting a fresh value forces a
        // resend that both servers receive.
        self.run(&["set-option", "-g", "status-left", "[tmate] "]);
        true
    }

    /// Clears the pane and waits for a bare prompt, so what follows starts
    /// from the same state on every run and on every server. Typing before
    /// the prompt is back races `clear`: the tty echoes the next command
    /// before the screen is wiped and one side loses a line.
    pub fn clear(&self) {
        self.send_keys(&["clear", "Enter"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pane = self.run(&["capture-pane", "-p"]);
            let lines: Vec<&str> = pane.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.len() == 1 && lines[0].trim_end().ends_with('$') {
                break;
            }
            if Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    fn cmd(&self) -> Command {
        self_cmd(self)
    }
}

fn self_cmd(host: &Host) -> Command {
    {
        let mut c = Command::new(&host.tmate);
        c.arg("-f").arg(&host.conf).arg("-S").arg(&host.sock);
        c.env("TERM", "xterm-256color")
            .env("PS1", "$ ")
            .env("ENV", "/dev/null");
        c
    }
}

impl Host {
    pub fn run(&self, args: &[&str]) -> String {
        let out = self.cmd().args(args).output().expect("run tmate");
        assert!(
            out.status.success(),
            "tmate {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Like action-tmate: blocks until the server has answered READY.
    pub fn wait_ready(&self, timeout: Duration) -> bool {
        let mut child = self.cmd().args(["wait", "tmate-ready"]).spawn().unwrap();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        false
    }

    pub fn display(&self, format: &str) -> String {
        self.run(&["display", "-p", format])
    }

    pub fn token(&self) -> String {
        let ssh = self.display("#{tmate_ssh}");
        ssh.rsplit_once(' ')
            .unwrap()
            .1
            .split_once('@')
            .unwrap()
            .0
            .to_string()
    }

    pub fn token_ro(&self) -> String {
        let ssh = self.display("#{tmate_ssh_ro}");
        ssh.rsplit_once(' ')
            .unwrap()
            .1
            .split_once('@')
            .unwrap()
            .0
            .to_string()
    }

    pub fn send_keys(&self, keys: &[&str]) {
        let mut args = vec!["send-keys"];
        args.extend_from_slice(keys);
        self.run(&args);
    }

    pub fn messages(&self) -> Vec<String> {
        self.run(&["show-messages"])
            .lines()
            .map(|l| l.to_string())
            .collect()
    }

    pub fn kill(&self) {
        let _ = self.cmd().arg("kill-server").output();
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.kill();
        if let Some(mut attached) = self.attached.take() {
            let _ = attached.kill();
            let _ = attached.wait();
        }
        let _ = std::fs::remove_file(&self.sock);
    }
}

struct ViewerHandler;

impl client::Handler for ViewerHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Outcome of a viewer's authentication attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum ViewerAuth {
    Accepted,
    Rejected,
}

/// A scripted `ssh <token>@server` whose output feeds a terminal emulator.
pub struct Viewer {
    channel: russh::ChannelWriteHalf<client::Msg>,
    screen: Arc<Mutex<vt100::Parser>>,
    reader: tokio::task::JoinHandle<()>,
    pub cols: u16,
    pub rows: u16,
}

impl Viewer {
    pub async fn connect(
        target: &Target,
        user: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Viewer, ViewerAuth> {
        Self::connect_with_key(target, user, None, cols, rows).await
    }

    pub async fn connect_with_key(
        target: &Target,
        user: &str,
        key: Option<russh::keys::PrivateKey>,
        cols: u16,
        rows: u16,
    ) -> Result<Viewer, ViewerAuth> {
        let config = Arc::new(client::Config::default());
        let mut session =
            client::connect(config, (target.host.as_str(), target.port), ViewerHandler)
                .await
                .expect("connect");
        let ok = match key {
            None => matches!(
                session.authenticate_none(user).await.expect("auth"),
                russh::client::AuthResult::Success
            ),
            Some(key) => {
                let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
                matches!(
                    session
                        .authenticate_publickey(user, key)
                        .await
                        .expect("auth"),
                    russh::client::AuthResult::Success
                )
            }
        };
        if !ok {
            return Err(ViewerAuth::Rejected);
        }
        let channel = session.channel_open_session().await.expect("open channel");
        channel
            .request_pty(
                true,
                "xterm-256color",
                cols.into(),
                rows.into(),
                0,
                0,
                &[(Pty::TTY_OP_END, 0)],
            )
            .await
            .expect("pty");
        channel.request_shell(true).await.expect("shell");
        let screen = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let reader = tokio::spawn(reader_task(rx, screen.clone()));
        // Forward channel messages to the emulator without borrowing the channel.
        let channel = forward_channel(channel, tx);
        Ok(Viewer {
            channel,
            screen,
            reader,
            cols,
            rows,
        })
    }

    pub async fn send(&self, bytes: &[u8]) {
        self.channel
            .data_bytes(bytes::Bytes::copy_from_slice(bytes))
            .await
            .expect("send");
    }

    pub async fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.screen.lock().await.screen_mut().set_size(rows, cols);
        self.channel
            .window_change(cols.into(), rows.into(), 0, 0)
            .await
            .expect("resize");
    }

    /// Visible rows, trailing whitespace trimmed.
    pub async fn rows(&self) -> Vec<String> {
        let s = self.screen.lock().await;
        s.screen()
            .rows(0, self.cols)
            .map(|r| r.trim_end().to_string())
            .collect()
    }

    /// Everything but the bottom (status) row.
    pub async fn pane_rows(&self) -> Vec<String> {
        let mut rows = self.rows().await;
        rows.pop();
        rows
    }

    pub async fn status_row(&self) -> String {
        self.rows().await.pop().unwrap_or_default()
    }

    /// Waits until the status row satisfies `pred`, or panics with it.
    pub async fn wait_for_status(&self, timeout: Duration, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let status = self.status_row().await;
            if pred(&status) {
                return status;
            }
            if Instant::now() > deadline {
                panic!("timed out; status row was {status:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Waits until `pred` holds for the pane rows, or panics with the last screen.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&[String]) -> bool,
    ) -> Vec<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let rows = self.pane_rows().await;
            if pred(&rows) {
                return rows;
            }
            if Instant::now() > deadline {
                panic!("timed out; screen was:\n{}", rows.join("\n"));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn wait_for_text(&self, text: &str) -> Vec<String> {
        let text = text.to_string();
        self.wait_for(Duration::from_secs(10), move |rows| {
            rows.iter().any(|r| r.contains(&text))
        })
        .await
    }

    pub async fn close(self) {
        let _ = self.channel.eof().await;
        let _ = self.channel.close().await;
        self.reader.abort();
    }
}

async fn reader_task(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    screen: Arc<Mutex<vt100::Parser>>,
) {
    while let Some(bytes) = rx.recv().await {
        screen.lock().await.process(&bytes);
    }
}

/// Splits a channel: the returned half is for sending; received data goes to `tx`.
fn forward_channel(
    channel: russh::Channel<client::Msg>,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> russh::ChannelWriteHalf<client::Msg> {
    let (mut reader, writer) = channel.split();
    tokio::spawn(async move {
        while let Some(msg) = reader.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if tx.send(data.to_vec()).is_err() {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
    });
    writer
}
