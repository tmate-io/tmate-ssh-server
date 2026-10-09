//! Connection handling: PROXY protocol, the grace period and exec requests.
//! The tests that need a session use a real tmate client and are skipped
//! when `tmate` is not in PATH; the others only need the server binary.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client;
use support::{Host, NewServer, Target, Viewer};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

macro_rules! require_tmate {
    () => {
        if support::tmate_binary().is_none() {
            eprintln!("skipping: tmate not in PATH");
            return;
        }
    };
}

/// Connects, sends `preamble`, and returns the first line the server sends
/// (empty on EOF) within `timeout`.
async fn first_line_after(port: u16, preamble: &[u8], timeout: Duration) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(preamble).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // A reset (the server closed with our bytes unread) counts as closed.
    let _ = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .expect("server neither answered nor closed in time");
    line
}

#[tokio::test]
async fn without_the_flag_the_banner_comes_first() {
    let server = NewServer::start();
    let line = first_line_after(server.target.port, b"", Duration::from_secs(5)).await;
    assert_eq!(line.trim_end(), "SSH-2.0-tmate");
}

#[tokio::test]
async fn proxy_header_is_read_before_ssh() {
    let server = NewServer::start_with_args(&["--proxy-protocol"]);
    let port = server.target.port;
    let five = Duration::from_secs(5);
    for header in [
        &b"PROXY TCP4 192.0.2.10 10.0.0.1 51234 2200\r\n"[..],
        b"PROXY TCP6 2001:db8::1 ::1 51234 2200\r\n",
        b"PROXY UNKNOWN\r\n",
    ] {
        let line = first_line_after(port, header, five).await;
        assert_eq!(
            line.trim_end(),
            "SSH-2.0-tmate",
            "after {:?}",
            String::from_utf8_lossy(header)
        );
    }
    // An invalid header closes the connection without an SSH banner.
    for garbage in [
        &b"SSH-2.0-OpenSSH_9.9\r\n"[..],
        b"PROXY TCP4 192.0.2.10 10.0.0.1 51234\r\n",
        b"PROXY TCP4 2001:db8::1 ::1 1 2\r\n",
    ] {
        let line = first_line_after(port, garbage, five).await;
        assert_eq!(line, "", "after {:?}", String::from_utf8_lossy(garbage));
    }
}

#[tokio::test]
async fn grace_period_closes_idle_connections() {
    let server = NewServer::start();
    let started = Instant::now();
    // No SSH banner, nothing at all: the old server's alarm(20) case.
    let line = first_line_after(server.target.port, b"", Duration::from_secs(30)).await;
    assert_eq!(line.trim_end(), "SSH-2.0-tmate");
    let mut stream = TcpStream::connect(("127.0.0.1", server.target.port))
        .await
        .unwrap();
    let mut sink = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut sink))
        .await
        .expect("idle connection was not closed")
        .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(19) && elapsed < Duration::from_secs(30),
        "closed after {elapsed:?}"
    );
}

/// A stand-in for a load balancer: accepts on a local port, opens a
/// connection to the server, writes a PROXY line claiming `source` and
/// then copies bytes both ways.
async fn proxy_in_front_of(server_port: u16, source: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut upstream = TcpStream::connect(("127.0.0.1", server_port))
                    .await
                    .unwrap();
                let header = format!("PROXY TCP4 {source} 127.0.0.1 40000 {server_port}\r\n");
                upstream.write_all(header.as_bytes()).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    port
}

// Multi-threaded so the proxy task keeps running while the blocking tmate
// host start-up holds the test thread.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_source_ip_is_the_viewer_ip_in_notices() {
    require_tmate!();
    let server = NewServer::start_with_args(&["--proxy-protocol"]);
    let port = proxy_in_front_of(server.target.port, "192.0.2.10").await;
    let target = Target {
        port,
        ..server.target.clone()
    };
    let host = Host::start(&target);
    assert!(host.prepare());
    let viewer = Viewer::connect(&target, &host.token(), 80, 24)
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let joined = loop {
        let messages = host.messages();
        if let Some(m) = messages.iter().find(|m| m.contains("A mate has joined")) {
            break m.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no join notice; messages were {messages:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(joined.contains("(192.0.2.10)"), "{joined}");
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

#[tokio::test]
async fn exec_requests_are_refused_with_an_explanation() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());

    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, ("127.0.0.1", server.target.port), ExecClient)
        .await
        .unwrap();
    let auth = session.authenticate_none(&host.token()).await.unwrap();
    assert!(matches!(auth, client::AuthResult::Success));
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, "ls -la").await.unwrap();

    let mut output = Vec::new();
    let mut exit_status = None;
    let deadline = tokio::time::sleep(Duration::from_secs(10));
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
    assert_eq!(
        String::from_utf8_lossy(&output),
        "tmate: command execution is not supported on this server\r\n"
    );
    assert_eq!(exit_status, Some(1));
}
