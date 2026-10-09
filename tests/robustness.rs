//! Abuse and load: a misbehaving host must only lose its own session, and
//! concurrent sessions must stay separate.

mod support;

use std::sync::Arc;
use std::time::Duration;

use russh::client;
use support::{Host, NewServer, Target, Viewer};

macro_rules! require_tmate {
    () => {
        if support::tmate_binary().is_none() {
            eprintln!("skipping: tmate not in PATH");
            return;
        }
    };
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

/// A host that speaks whatever bytes the test gives it on the `tmate`
/// subsystem channel, like a modified client would.
struct FakeHost {
    channel: russh::ChannelWriteHalf<client::Msg>,
    reader: russh::ChannelReadHalf,
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
        let (reader, channel) = channel.split();
        FakeHost { channel, reader }
    }

    /// Fails once the server has cut us off. russh's `data_bytes` alone
    /// is not enough: when the server's window is used up it waits for a
    /// window adjustment, and nothing wakes it if the session ends
    /// instead, so the send is raced against the channel closing.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let data = bytes::Bytes::copy_from_slice(bytes);
        tokio::select! {
            sent = self.channel.data_bytes(data) => sent.map_err(|_| ()),
            () = closed(&mut self.reader) => Err(()),
        }
    }

    /// Waits for the server to close the channel or drop the connection.
    async fn wait_closed(&mut self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, closed(&mut self.reader))
            .await
            .is_ok()
    }
}

/// Resolves when the server closes the channel or the connection.
async fn closed(reader: &mut russh::ChannelReadHalf) {
    loop {
        match reader.wait().await {
            None | Some(russh::ChannelMsg::Close) | Some(russh::ChannelMsg::Eof) => return,
            _ => {}
        }
    }
}

/// Minimal msgpack writers for the few shapes the tests need.
fn mp_array(n: usize, out: &mut Vec<u8>) {
    assert!(n < 16);
    out.push(0x90 | n as u8);
}

fn mp_int(v: i64, out: &mut Vec<u8>) {
    assert!((0..=0x7f).contains(&v));
    out.push(v as u8);
}

fn mp_str(s: &[u8], out: &mut Vec<u8>) {
    out.push(0xdb);
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn header_and_ready() -> Vec<u8> {
    let mut out = Vec::new();
    mp_array(3, &mut out);
    mp_int(0, &mut out); // HEADER
    mp_int(6, &mut out);
    mp_str(b"2.4.0", &mut out);
    mp_array(1, &mut out);
    mp_int(9, &mut out); // READY
    out
}

fn pty_data(pane: i64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    mp_array(3, &mut out);
    mp_int(2, &mut out); // PTY_DATA
    mp_int(pane, &mut out);
    mp_str(payload, &mut out);
    out
}

async fn assert_server_still_serves(target: &Target) {
    let host = Host::start(target);
    assert!(host.prepare(), "server stopped answering real hosts");
    host.send_keys(&["echo still-alive", "Enter"]);
    let viewer = Viewer::connect(target, &host.token(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("still-alive").await;
    viewer.close().await;
}

#[tokio::test]
async fn garbage_from_a_host_only_ends_that_session() {
    require_tmate!();
    let server = NewServer::start();
    let bystander = Host::start(&server.target);
    assert!(bystander.prepare());
    let watcher = Viewer::connect(&server.target, &bystander.token(), 80, 24)
        .await
        .unwrap();
    watcher.wait_for_text("$").await;

    // 1. Not msgpack at all.
    let mut junk = FakeHost::connect(&server.target).await;
    let noise: Vec<u8> = (0..65536u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let _ = junk.send(&noise).await;
    assert!(
        junk.wait_closed(Duration::from_secs(10)).await,
        "garbage host was not disconnected"
    );

    // 2. A frame claiming to be 4 GiB.
    let mut oversize = FakeHost::connect(&server.target).await;
    let _ = oversize.send(&[0xdd, 0xff, 0xff, 0xff, 0xff]).await;
    assert!(
        oversize.wait_closed(Duration::from_secs(10)).await,
        "oversize frame was not rejected"
    );

    // 3. Well-formed messages in the wrong order / for panes that don't exist.
    let mut confused = FakeHost::connect(&server.target).await;
    let _ = confused.send(&pty_data(42, b"hello")).await;
    let mut ready = header_and_ready();
    ready.extend(pty_data(7, &[0x1b; 4096]));
    let _ = confused.send(&ready).await;
    // Whether this host is dropped or ignored, it must not affect anyone else.
    tokio::time::sleep(Duration::from_millis(500)).await;

    bystander.send_keys(&["echo bystander-fine", "Enter"]);
    watcher.wait_for_text("bystander-fine").await;
    watcher.close().await;
    assert_server_still_serves(&server.target).await;
}

#[tokio::test]
async fn host_flood_does_not_starve_other_sessions() {
    require_tmate!();
    let server = NewServer::start();
    let bystander = Host::start(&server.target);
    assert!(bystander.prepare());
    let watcher = Viewer::connect(&server.target, &bystander.token(), 80, 24)
        .await
        .unwrap();
    watcher.wait_for_text("$").await;

    let mut flooder = FakeHost::connect(&server.target).await;
    let _ = flooder.send(&header_and_ready()).await;
    // Layout with one 80x24 pane so PTY_DATA has somewhere to go.
    let mut layout = Vec::new();
    mp_array(5, &mut layout);
    mp_int(1, &mut layout); // SYNC_LAYOUT
    mp_int(80, &mut layout);
    mp_int(24, &mut layout);
    mp_array(1, &mut layout);
    mp_array(4, &mut layout);
    mp_int(0, &mut layout);
    mp_str(b"flood", &mut layout);
    mp_array(1, &mut layout);
    mp_array(5, &mut layout);
    for v in [0, 80, 24, 0, 0] {
        mp_int(v, &mut layout);
    }
    mp_int(0, &mut layout);
    mp_int(0, &mut layout);
    let _ = flooder.send(&layout).await;

    let chunk = pty_data(0, &vec![b'x'; 16 * 1024]);
    let flood = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < 64 * 1024 * 1024 {
            if flooder.send(&chunk).await.is_err() {
                break;
            }
            sent += chunk.len();
        }
        sent
    });

    // Meanwhile a normal session must stay responsive.
    let started = std::time::Instant::now();
    bystander.send_keys(&["echo during-flood", "Enter"]);
    watcher.wait_for_text("during-flood").await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "bystander starved by the flood"
    );
    let sent = flood.await.unwrap();
    eprintln!("flooder sent {} MiB before stopping", sent / (1024 * 1024));
    watcher.close().await;
    assert_server_still_serves(&server.target).await;
}

#[tokio::test]
async fn concurrent_sessions_do_not_leak_into_each_other() {
    require_tmate!();
    let server = NewServer::start();
    const N: usize = 6;
    let hosts: Vec<Host> = (0..N).map(|_| Host::start(&server.target)).collect();
    for host in &hosts {
        assert!(host.prepare());
    }
    let mut viewers = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        host.send_keys(&[&format!("echo secret-{i}-only"), "Enter"]);
        viewers.push(
            Viewer::connect(&server.target, &host.token(), 80, 24)
                .await
                .unwrap(),
        );
    }
    for (i, viewer) in viewers.iter().enumerate() {
        let rows = viewer.wait_for_text(&format!("secret-{i}-only")).await;
        let joined = rows.join("\n");
        for j in 0..N {
            if j != i {
                assert!(
                    !joined.contains(&format!("secret-{j}-only")),
                    "viewer {i} saw session {j}'s output"
                );
            }
        }
    }
    // Tokens are not reusable across sessions.
    let other = &hosts[1];
    let mut cross = Viewer::connect(&server.target, &other.token(), 80, 24)
        .await
        .unwrap();
    cross.send(b"echo typed-into-1\r").await;
    cross.wait_for_text("typed-into-1").await;
    assert!(
        !hosts[0]
            .run(&["capture-pane", "-p"])
            .contains("typed-into-1")
    );
    cross.resize(50, 12).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        hosts[0].display("#{pane_width}x#{pane_height}"),
        "80x23",
        "resize leaked across sessions"
    );
    cross.close().await;
    for viewer in viewers {
        viewer.close().await;
    }
}
