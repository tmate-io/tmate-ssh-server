//! The websocket backend mode (`-w`/`-z`): the server connects every
//! session to a backend and speaks the control protocol of the old
//! `tmate-websocket.c`. A fake backend on a local port plays the Elixir
//! service's part, scripted by each test, with a real tmate 2.4.0 host on
//! the other side. Skipped (with a message) when `tmate` isn't installed.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client;
use support::{Host, NewServer, Viewer, ViewerAuth};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};

use mp::V;

macro_rules! require_tmate {
    () => {
        if support::tmate_binary().is_none() {
            eprintln!("skipping: tmate not in PATH");
            return;
        }
    };
}

/// Just enough MessagePack for the control protocol.
mod mp {
    #[derive(Debug, Clone, PartialEq)]
    pub enum V {
        Nil,
        Bool(bool),
        Int(i64),
        Str(Vec<u8>),
        Arr(Vec<V>),
    }

    impl V {
        pub fn s(text: &str) -> V {
            V::Str(text.as_bytes().to_vec())
        }

        pub fn arr(&self) -> &[V] {
            match self {
                V::Arr(a) => a,
                other => panic!("not an array: {other:?}"),
            }
        }

        pub fn int(&self) -> i64 {
            match self {
                V::Int(i) => *i,
                other => panic!("not an int: {other:?}"),
            }
        }

        pub fn text(&self) -> String {
            match self {
                V::Str(b) => String::from_utf8_lossy(b).into_owned(),
                other => panic!("not a string: {other:?}"),
            }
        }
    }

    pub fn encode(v: &V, out: &mut Vec<u8>) {
        match v {
            V::Nil => out.push(0xc0),
            V::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
            V::Int(i) => {
                if (0..=0x7f).contains(i) {
                    out.push(*i as u8);
                } else if (-32..0).contains(i) {
                    out.push(*i as i8 as u8);
                } else {
                    out.push(0xd3);
                    out.extend_from_slice(&i.to_be_bytes());
                }
            }
            V::Str(s) => {
                if s.len() < 32 {
                    out.push(0xa0 | s.len() as u8);
                } else {
                    out.push(0xdb);
                    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
                }
                out.extend_from_slice(s);
            }
            V::Arr(items) => {
                if items.len() < 16 {
                    out.push(0x90 | items.len() as u8);
                } else {
                    out.push(0xdd);
                    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
                }
                for item in items {
                    encode(item, out);
                }
            }
        }
    }

    /// One value and the bytes it took, `None` while incomplete.
    pub fn decode(buf: &[u8]) -> Option<(V, usize)> {
        let b = *buf.first()?;
        let be = |n: usize| -> Option<u64> {
            let bytes = buf.get(1..1 + n)?;
            Some(bytes.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)))
        };
        let payload = |hdr: usize, len: usize| -> Option<(V, usize)> {
            let bytes = buf.get(hdr..hdr + len)?;
            Some((V::Str(bytes.to_vec()), hdr + len))
        };
        let array = |hdr: usize, count: usize| -> Option<(V, usize)> {
            let mut pos = hdr;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (v, n) = decode(&buf[pos..])?;
                items.push(v);
                pos += n;
            }
            Some((V::Arr(items), pos))
        };
        Some(match b {
            0x00..=0x7f => (V::Int(i64::from(b)), 1),
            0xe0..=0xff => (V::Int(i64::from(b as i8)), 1),
            0xc0 => (V::Nil, 1),
            0xc2 => (V::Bool(false), 1),
            0xc3 => (V::Bool(true), 1),
            0xcc => (V::Int(be(1)? as i64), 2),
            0xcd => (V::Int(be(2)? as i64), 3),
            0xce => (V::Int(be(4)? as i64), 5),
            0xcf => (V::Int(be(8)? as i64), 9),
            0xd0 => (V::Int(i64::from(be(1)? as u8 as i8)), 2),
            0xd1 => (V::Int(i64::from(be(2)? as u16 as i16)), 3),
            0xd2 => (V::Int(i64::from(be(4)? as u32 as i32)), 5),
            0xd3 => (V::Int(be(8)? as i64), 9),
            0xa0..=0xbf => payload(1, usize::from(b & 0x1f))?,
            0xd9 | 0xc4 => payload(2, be(1)? as usize)?,
            0xda | 0xc5 => payload(3, be(2)? as usize)?,
            0xdb | 0xc6 => payload(5, be(4)? as usize)?,
            0x90..=0x9f => array(1, usize::from(b & 0x0f))?,
            0xdc => array(3, be(2)? as usize)?,
            0xdd => array(5, be(4)? as usize)?,
            other => panic!("unsupported msgpack byte {other:#x}"),
        })
    }
}

// Control protocol message types.
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
// Daemon protocol message types.
const OUT_HEADER: i64 = 0;
const OUT_PTY_DATA: i64 = 2;
const OUT_READY: i64 = 9;
const OUT_UNAME: i64 = 13;
const IN_NOTIFY: i64 = 0;
const IN_SET_ENV: i64 = 4;
const IN_READY: i64 = 5;

/// One connection from the server, as the backend sees it.
struct Conn {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    buf: Vec<u8>,
}

impl Conn {
    async fn recv(&mut self) -> V {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some((v, n)) = mp::decode(&self.buf) {
                self.buf.drain(..n);
                return v;
            }
            let mut chunk = vec![0u8; 65536];
            let left = deadline.saturating_duration_since(Instant::now());
            let n = tokio::time::timeout(left, self.rd.read(&mut chunk))
                .await
                .expect("backend: no message from the server in time")
                .expect("backend: read");
            assert!(n > 0, "backend: the server closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Whether the server closed the connection within `timeout`.
    async fn closed(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let mut chunk = vec![0u8; 65536];
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, self.rd.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    /// Messages up to and including the first one `pred` accepts.
    async fn recv_until(&mut self, pred: impl Fn(&V) -> bool) -> Vec<V> {
        let mut seen = Vec::new();
        loop {
            let v = self.recv().await;
            let done = pred(&v);
            seen.push(v);
            if done {
                return seen;
            }
        }
    }

    async fn send(&mut self, v: V) {
        let mut out = Vec::new();
        mp::encode(&v, &mut out);
        self.wr.write_all(&out).await.expect("backend: write");
    }

    async fn fwd(&mut self, msg: V) {
        self.send(V::Arr(vec![V::Int(CTL_DEAMON_FWD_MSG), msg]))
            .await;
    }

    async fn notify(&mut self, text: &str) {
        self.fwd(V::Arr(vec![V::Int(IN_NOTIFY), V::s(text)])).await;
    }

    async fn set_env(&mut self, name: &str, value: &str) {
        self.fwd(V::Arr(vec![V::Int(IN_SET_ENV), V::s(name), V::s(value)]))
            .await;
    }

    /// What the Elixir backend's `finalize_session_init` sends once the
    /// host is ready: notices, links, and READY.
    async fn finalize(&mut self, ssh_cmd_fmt: &str, rw: &str, ro: &str) {
        let ssh = ssh_cmd_fmt.replace("%s", rw);
        let ssh_ro = ssh_cmd_fmt.replace("%s", ro);
        let web = format!("http://fake/t/{rw}");
        let web_ro = format!("http://fake/t/{ro}");
        self.notify("Note: clear your terminal before sharing readonly access")
            .await;
        self.notify(&format!("web session read only: {web_ro}"))
            .await;
        self.notify(&format!("ssh session read only: {ssh_ro}"))
            .await;
        self.notify(&format!("web session: {web}")).await;
        self.notify(&format!("ssh session: {ssh}")).await;
        self.set_env("tmate_web_ro", &web_ro).await;
        self.set_env("tmate_ssh_ro", &ssh_ro).await;
        self.set_env("tmate_web", &web).await;
        self.set_env("tmate_ssh", &ssh).await;
        self.set_env("tmate_num_clients", "0").await;
        self.set_env("tmate_reconnection_data", "fake|data").await;
        self.fwd(V::Arr(vec![V::Int(IN_READY)])).await;
    }
}

/// Listens where the server is told the backend is.
struct FakeBackend {
    port: u16,
    conns: Mutex<mpsc::UnboundedReceiver<Conn>>,
}

impl FakeBackend {
    async fn start() -> FakeBackend {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (rd, wr) = stream.into_split();
                if tx
                    .send(Conn {
                        rd,
                        wr,
                        buf: Vec::new(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        FakeBackend {
            port,
            conns: Mutex::new(rx),
        }
    }

    async fn accept(&self) -> Conn {
        tokio::time::timeout(Duration::from_secs(15), self.conns.lock().await.recv())
            .await
            .expect("backend: the server never connected")
            .expect("backend: accept loop ended")
    }

    fn server_args(&self) -> Vec<String> {
        vec![
            "-w".into(),
            "127.0.0.1".into(),
            "-z".into(),
            self.port.to_string(),
        ]
    }
}

/// A session's header as the backend got it.
struct Header {
    ip: String,
    rw: String,
    ro: String,
    ssh_cmd_fmt: String,
    client_version: String,
    protocol: i64,
}

fn parse_header(v: &V) -> Header {
    let a = v.arr();
    assert_eq!(a.len(), 9, "{v:?}");
    assert_eq!(a[0].int(), CTL_HEADER);
    assert_eq!(a[1].int(), 2, "control protocol version");
    assert_eq!(a[3], V::Nil, "the host authenticated without a key");
    Header {
        ip: a[2].text(),
        rw: a[4].text(),
        ro: a[5].text(),
        ssh_cmd_fmt: a[6].text(),
        client_version: a[7].text(),
        protocol: a[8].int(),
    }
}

fn is_fwd_of(v: &V, kind: i64) -> bool {
    let a = v.arr();
    a[0].int() == CTL_DEAMON_OUT_MSG && a[1].arr()[0].int() == kind
}

/// A session up to the host's READY: the connection, its header and the
/// messages forwarded so far (HEADER first, READY last).
async fn session_up(backend: &FakeBackend) -> (Conn, Header, Vec<V>) {
    let mut conn = backend.accept().await;
    let header = parse_header(&conn.recv().await);
    let forwarded = conn.recv_until(|v| is_fwd_of(v, OUT_READY)).await;
    (conn, header, forwarded)
}

fn start_server(backend: &FakeBackend) -> NewServer {
    let args = backend.server_args();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    NewServer::start_with_args(&args)
}

async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

// The tmate host is started synchronously; the fake backend's accept loop
// must keep running meanwhile, hence the multi-threaded runtime.
#[tokio::test(flavor = "multi_thread")]
async fn header_then_every_host_message_forwarded_and_the_backends_answers_reach_the_host() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, forwarded) = session_up(&backend).await;

    assert_eq!(header.ip, "127.0.0.1");
    assert_eq!(header.rw.len(), 25);
    assert!(
        header.ro.starts_with("ro-") && header.ro.len() == 28,
        "{}",
        header.ro
    );
    assert_eq!(
        header.ssh_cmd_fmt,
        format!("ssh -p{} %s@127.0.0.1", server.target.port)
    );
    assert_eq!(header.client_version, "2.4.0");
    assert_eq!(header.protocol, 6);

    // The host's own messages, verbatim and in order.
    assert_eq!(
        forwarded[0],
        V::Arr(vec![
            V::Int(CTL_DEAMON_OUT_MSG),
            V::Arr(vec![V::Int(OUT_HEADER), V::Int(6), V::s("2.4.0")])
        ])
    );
    let uname = forwarded
        .iter()
        .find(|v| is_fwd_of(v, OUT_UNAME))
        .expect("uname forwarded");
    assert_eq!(uname.arr()[1].arr().len(), 6, "{uname:?}");
    assert_eq!(
        forwarded.last().unwrap(),
        &V::Arr(vec![
            V::Int(CTL_DEAMON_OUT_MSG),
            V::Arr(vec![V::Int(OUT_READY)])
        ])
    );

    // Nothing reached the host yet: the backend speaks first.
    assert!(!host.wait_ready(Duration::from_millis(500)));
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare(), "READY from the backend did not get through");
    assert_eq!(
        host.display("#{tmate_ssh}"),
        format!("ssh -p{} {}@127.0.0.1", server.target.port, header.rw)
    );
    assert_eq!(
        host.display("#{tmate_web}"),
        format!("http://fake/t/{}", header.rw)
    );
    assert_eq!(host.display("#{tmate_num_clients}"), "0");
    let messages = host.messages().join("\n");
    assert!(
        messages.contains(&format!("web session: http://fake/t/{}", header.rw)),
        "{messages}"
    );
    assert!(
        !messages.contains("Named sessions are not supported"),
        "{messages}"
    );

    // Later output is forwarded too, as PTY_DATA.
    host.send_keys(&["echo fwd-check", "Enter"]);
    let seen = conn
        .recv_until(|v| {
            is_fwd_of(v, OUT_PTY_DATA) && v.arr()[1].arr()[2].text().contains("fwd-check")
        })
        .await;
    assert!(!seen.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn viewers_are_announced_to_the_backend_with_ip_key_and_access() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());

    let viewer = Viewer::connect(&server.target, &header.rw, 80, 24)
        .await
        .unwrap();
    let join = conn
        .recv_until(|v| v.arr()[0].int() == CTL_CLIENT_JOIN)
        .await
        .pop()
        .unwrap();
    let a = join.arr();
    assert_eq!(a.len(), 5);
    let rw_id = a[1].int();
    assert_eq!(a[2], V::s("127.0.0.1"));
    assert_eq!(a[3], V::Nil, "no key");
    assert_eq!(a[4], V::Bool(false), "read-write");
    // The backend, not the server, tells the host about it.
    assert_eq!(host.display("#{tmate_num_clients}"), "0");
    assert!(!host.messages().join("\n").contains("A mate has joined"));
    conn.set_env("tmate_num_clients", "1").await;
    conn.notify("A mate has joined (127.0.0.1) -- 1 client currently connected")
        .await;
    assert!(wait_until(|| host.display("#{tmate_num_clients}") == "1").await);
    assert!(host.messages().join("\n").contains("A mate has joined"));

    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let ro = Viewer::connect_with_key(&server.target, &header.ro, Some(key.clone()), 80, 24)
        .await
        .unwrap();
    let join = conn
        .recv_until(|v| v.arr()[0].int() == CTL_CLIENT_JOIN)
        .await
        .pop()
        .unwrap();
    let a = join.arr();
    let ro_id = a[1].int();
    assert_ne!(ro_id, rw_id);
    assert_eq!(a[3], V::s(&key.public_key().to_openssh().unwrap()));
    assert_eq!(a[4], V::Bool(true), "read-only");

    viewer.close().await;
    let left = conn
        .recv_until(|v| v.arr()[0].int() == CTL_CLIENT_LEFT)
        .await
        .pop()
        .unwrap();
    assert_eq!(left, V::Arr(vec![V::Int(CTL_CLIENT_LEFT), V::Int(rw_id)]));
    ro.close().await;
    let left = conn
        .recv_until(|v| v.arr()[0].int() == CTL_CLIENT_LEFT)
        .await
        .pop()
        .unwrap();
    assert_eq!(left.arr()[1].int(), ro_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_requests_are_answered_from_the_pane_grids() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());
    host.send_keys(&["echo snapshot-marker", "Enter"]);
    conn.recv_until(|v| {
        is_fwd_of(v, OUT_PTY_DATA) && v.arr()[1].arr()[2].text().contains("snapshot-marker")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    conn.send(V::Arr(vec![V::Int(CTL_REQUEST_SNAPSHOT), V::Int(300)]))
        .await;
    let snap = conn
        .recv_until(|v| v.arr()[0].int() == CTL_SNAPSHOT)
        .await
        .pop()
        .unwrap();
    // [CTL_SNAPSHOT, [[pane_id, [cx, cy], mode, [[line_utf8, [cell, ...]], ...]], ...]]
    let panes = snap.arr()[1].arr();
    assert_eq!(panes.len(), 1, "{snap:?}");
    let pane = panes[0].arr();
    assert_eq!(pane.len(), 4);
    assert_eq!(pane[0].int(), 0, "pane %0");
    let cursor = pane[1].arr();
    assert_eq!(cursor.len(), 2);
    assert_eq!(cursor[0].int(), 2, "cursor after the prompt");
    assert!(pane[2].int() & 0x1 != 0, "MODE_CURSOR");
    let lines = pane[3].arr();
    let texts: Vec<String> = lines.iter().map(|l| l.arr()[0].text()).collect();
    assert!(
        texts.iter().any(|t| t == "snapshot-marker"),
        "lines were {texts:?}"
    );
    for line in lines {
        let l = line.arr();
        assert_eq!(l.len(), 2);
        assert_eq!(
            l[0].text().chars().count(),
            l[1].arr().len(),
            "one cell word per character: {line:?}"
        );
        for cell in l[1].arr() {
            let w = cell.int();
            assert_eq!(w & 0xff, 8, "default fg in {w:#x}");
            assert_eq!((w >> 8) & 0xff, 8, "default bg in {w:#x}");
        }
    }
    // The limit cuts history: with none, only the screen's rows remain.
    conn.send(V::Arr(vec![V::Int(CTL_REQUEST_SNAPSHOT), V::Int(0)]))
        .await;
    let snap = conn
        .recv_until(|v| v.arr()[0].int() == CTL_SNAPSHOT)
        .await
        .pop()
        .unwrap();
    let rows: usize = host.display("#{pane_height}").parse().unwrap();
    assert!(snap.arr()[1].arr()[0].arr()[3].arr().len() <= rows);
}

#[tokio::test(flavor = "multi_thread")]
async fn pane_keys_from_the_backend_type_into_the_host() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());
    conn.send(V::Arr(vec![
        V::Int(CTL_PANE_KEYS),
        V::Int(-1),
        V::s("echo typed-by-backend\r"),
    ]))
    .await;
    assert!(
        wait_until(|| host
            .run(&["capture-pane", "-p"])
            .contains("typed-by-backend"))
        .await,
        "host pane was:\n{}",
        host.run(&["capture-pane", "-p"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_resize_takes_part_in_the_size_rule() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());
    let size = || host.display("#{pane_width}x#{pane_height}");

    // A web client alone sizes the pane.
    conn.send(V::Arr(vec![V::Int(CTL_RESIZE), V::Int(60), V::Int(20)]))
        .await;
    assert!(wait_until(|| size() == "60x20").await, "size is {}", size());
    // The smallest of the web client and the ssh viewer, per dimension.
    let mut viewer = Viewer::connect(&server.target, &header.rw, 100, 15)
        .await
        .unwrap();
    assert!(wait_until(|| size() == "60x14").await, "size is {}", size());
    viewer.resize(50, 30).await;
    assert!(wait_until(|| size() == "50x20").await, "size is {}", size());
    // No web client left: the ssh viewer alone.
    conn.send(V::Arr(vec![V::Int(CTL_RESIZE), V::Int(-1), V::Int(-1)]))
        .await;
    assert!(wait_until(|| size() == "50x29").await, "size is {}", size());
    viewer.close().await;
}

struct ExecClient;

impl client::Handler for ExecClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// `ssh user@server command`: the output and exit status.
async fn ssh_exec(port: u16, user: &str, command: &str) -> (String, Option<u32>) {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, ("127.0.0.1", port), ExecClient)
        .await
        .unwrap();
    let auth = session.authenticate_none(user).await.unwrap();
    assert!(matches!(auth, client::AuthResult::Success), "{auth:?}");
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut output = Vec::new();
    let mut exit_status = None;
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            _ = &mut deadline => panic!("channel never closed; output so far: {:?}", String::from_utf8_lossy(&output)),
        }
    }
    (String::from_utf8_lossy(&output).into_owned(), exit_status)
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_requests_and_unknown_tokens_go_to_the_backend() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());

    // `ssh token@host command`: CTL_EXEC on a connection of its own.
    let port = server.target.port;
    let token = header.rw.clone();
    let client = tokio::spawn(async move { ssh_exec(port, &token, "ls -la").await });
    let mut exec = backend.accept().await;
    assert_eq!(
        exec.recv().await,
        V::Arr(vec![
            V::Int(CTL_EXEC),
            V::s(&header.rw),
            V::s("127.0.0.1"),
            V::Nil,
            V::s("ls -la")
        ])
    );
    exec.send(V::Arr(vec![
        V::Int(CTL_EXEC_RESPONSE),
        V::Int(3),
        V::s("Invalid command\r\n"),
    ]))
    .await;
    assert_eq!(
        client.await.unwrap(),
        ("Invalid command\r\n".to_string(), Some(3))
    );
    assert!(exec.closed(Duration::from_secs(5)).await);

    // A token nobody holds: let in, then explained by the backend.
    let viewer = tokio::spawn({
        let target = server.target.clone();
        async move { Viewer::connect(&target, "no-such/session", 80, 24).await }
    });
    let mut exec = backend.accept().await;
    assert_eq!(
        exec.recv().await,
        V::Arr(vec![
            V::Int(CTL_EXEC),
            V::s("no-such/session"),
            V::s("127.0.0.1"),
            V::Nil,
            V::s("explain-session-not-found")
        ])
    );
    exec.send(V::Arr(vec![
        V::Int(CTL_EXEC_RESPONSE),
        V::Int(1),
        V::s("This session was closed 5 minutes ago.\r\n"),
    ]))
    .await;
    let viewer = viewer
        .await
        .unwrap()
        .expect("let in to hear the explanation");
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter().any(|r| r.contains("closed 5 minutes ago"))
        })
        .await;
    viewer.close().await;

    // Tokens that could never be a session name are still refused at auth.
    assert_eq!(
        Viewer::connect(&server.target, "no such", 80, 24)
            .await
            .err(),
        Some(ViewerAuth::Rejected)
    );

    // The session's own connection was not involved.
    host.send_keys(&["echo still-here", "Enter"]);
    conn.recv_until(|v| {
        is_fwd_of(v, OUT_PTY_DATA) && v.arr()[1].arr()[2].text().contains("still-here")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn renamed_sessions_are_reachable_under_the_new_tokens() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let sessions = tempfile::tempdir().unwrap();
    let mut args = backend.server_args();
    args.push("--sessions-dir".into());
    args.push(sessions.path().to_str().unwrap().into());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let server = NewServer::start_with_args(&args);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    // The files the backend renames: the old server's socket and symlink.
    assert!(sessions.path().join(&header.rw).is_file());
    assert_eq!(
        std::fs::read_link(sessions.path().join(&header.ro)).unwrap(),
        std::path::PathBuf::from(&header.rw)
    );
    let (rw, ro) = ("acme/demo", "ro-acme/demo");
    std::fs::rename(
        sessions.path().join(&header.rw),
        sessions.path().join("acme=demo"),
    )
    .unwrap();
    std::fs::remove_file(sessions.path().join(&header.ro)).unwrap();
    std::os::unix::fs::symlink("acme=demo", sessions.path().join("ro-acme=demo")).unwrap();
    conn.send(V::Arr(vec![V::Int(CTL_RENAME_SESSION), V::s(rw), V::s(ro)]))
        .await;
    conn.finalize(&header.ssh_cmd_fmt, rw, ro).await;
    assert!(host.prepare());
    assert_eq!(
        host.display("#{tmate_ssh}"),
        format!("ssh -p{} acme/demo@127.0.0.1", server.target.port)
    );

    host.send_keys(&["echo named-session", "Enter"]);
    let viewer = Viewer::connect(&server.target, rw, 80, 24).await.unwrap();
    viewer.wait_for_text("named-session").await;
    viewer.send(b"echo typed-into-named\r").await;
    viewer.wait_for_text("typed-into-named").await;
    let ro_viewer = Viewer::connect(&server.target, ro, 80, 24).await.unwrap();
    ro_viewer.wait_for_text("typed-into-named").await;
    ro_viewer.send(b"echo should-not-appear\r").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !host
            .run(&["capture-pane", "-p"])
            .contains("should-not-appear"),
        "read-only under the new token"
    );
    conn.recv_until(|v| v.arr()[0].int() == CTL_CLIENT_JOIN)
        .await;

    // The random tokens are gone; the backend explains them away.
    let old = tokio::spawn({
        let target = server.target.clone();
        let old = header.rw.clone();
        async move { Viewer::connect(&target, &old, 80, 24).await }
    });
    let mut exec = backend.accept().await;
    let msg = exec.recv().await;
    assert_eq!(msg.arr()[1], V::s(&header.rw));
    assert_eq!(msg.arr()[4], V::s("explain-session-not-found"));
    exec.send(V::Arr(vec![
        V::Int(CTL_EXEC_RESPONSE),
        V::Int(1),
        V::s("Invalid session token\r\n"),
    ]))
    .await;
    let old = old.await.unwrap().unwrap();
    old.wait_for_text("Invalid session token").await;
    old.close().await;
    viewer.close().await;
    ro_viewer.close().await;

    // The session's files go when it ends, under their renamed names.
    host.kill();
    assert!(conn.closed(Duration::from_secs(5)).await);
    assert!(
        wait_until(|| std::fs::read_dir(sessions.path()).unwrap().count() == 0).await,
        "left behind: {:?}",
        std::fs::read_dir(sessions.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_the_backend_ends_the_session_and_the_host_starts_over() {
    require_tmate!();
    let backend = FakeBackend::start().await;
    let server = start_server(&backend);
    let host = Host::start(&server.target);
    let (mut conn, header, _) = session_up(&backend).await;
    conn.finalize(&header.ssh_cmd_fmt, &header.rw, &header.ro)
        .await;
    assert!(host.prepare());
    let viewer = Viewer::connect(&server.target, &header.rw, 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
    conn.recv_until(|v| v.arr()[0].int() == CTL_CLIENT_JOIN)
        .await;

    drop(conn);
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter().any(|r| r.contains("session ended"))
        })
        .await;
    // tmate reconnects on its own: a new session, a new backend connection.
    let (mut conn2, header2, _) = session_up(&backend).await;
    assert_ne!(header2.rw, header.rw);
    conn2
        .finalize(&header2.ssh_cmd_fmt, &header2.rw, &header2.ro)
        .await;
    assert!(wait_until(|| host.display("#{tmate_ssh}").contains(&header2.rw)).await);
    assert!(
        Viewer::connect(&server.target, &header2.rw, 80, 24)
            .await
            .is_ok()
    );
    // A FIN is forwarded before the connection is closed.
    host.kill();
    let seen = conn2.recv_until(|v| is_fwd_of(v, 8)).await;
    assert!(!seen.is_empty());
    assert!(conn2.closed(Duration::from_secs(5)).await);
}

/// A host connection scripted by hand (auth `tmate`, subsystem `tmate`),
/// so what the server says before closing can be read without a tmate
/// client in the way.
async fn scripted_host(port: u16) -> russh::Channel<client::Msg> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, ("127.0.0.1", port), ExecClient)
        .await
        .unwrap();
    let auth = session.authenticate_none("tmate").await.unwrap();
    assert!(matches!(auth, client::AuthResult::Success), "{auth:?}");
    let channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "tmate").await.unwrap();
    channel
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_backend_refuses_the_session() {
    let port = support::free_port();
    let server = NewServer::start_with_args(&["-w", "127.0.0.1", "-z", &port.to_string()]);
    let mut host = scripted_host(server.target.port).await;
    // Say hello like a tmate 2.4.0 client; nothing of it is answered.
    let mut header = Vec::new();
    mp::encode(
        &V::Arr(vec![V::Int(OUT_HEADER), V::Int(6), V::s("2.4.0")]),
        &mut header,
    );
    host.data(&header[..]).await.unwrap();
    let mut received = Vec::new();
    let mut closed = false;
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    while !closed {
        tokio::select! {
            msg = host.wait() => match msg {
                Some(ChannelMsg::Data { data }) => received.extend_from_slice(&data),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => closed = true,
                Some(_) => {}
            },
            _ = &mut deadline => panic!("the server neither refused nor closed; got {received:?}"),
        }
    }
    // Two notices, then the channel is closed: no READY, no links.
    let mut msgs = Vec::new();
    let mut pos = 0;
    while let Some((v, n)) = mp::decode(&received[pos..]) {
        msgs.push(v);
        pos += n;
    }
    assert_eq!(pos, received.len(), "trailing bytes in {received:?}");
    assert_eq!(msgs.len(), 2, "{msgs:?}");
    assert_eq!(msgs[0].arr()[0].int(), IN_NOTIFY);
    assert!(
        msgs[0].arr()[1].text().contains("backend is unavailable"),
        "{msgs:?}"
    );
    assert_eq!(msgs[1].arr()[0].int(), IN_NOTIFY);
    assert!(
        !msgs.iter().any(|m| m.arr()[0].int() == IN_READY),
        "a session must not come up without its backend"
    );
}
