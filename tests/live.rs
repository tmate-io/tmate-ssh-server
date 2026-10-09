//! End-to-end tests against the Rust server with a real tmate 2.4.0 host and
//! scripted SSH viewers. Skipped (with a message) when `tmate` isn't installed.

mod support;

use std::time::Duration;

use support::{Host, NewServer, Viewer, ViewerAuth};

macro_rules! require_tmate {
    () => {
        if support::tmate_binary().is_none() {
            eprintln!("skipping: tmate not in PATH");
            return;
        }
    };
}

#[tokio::test]
async fn handshake_gives_links_like_action_tmate_expects() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare(), "wait tmate-ready did not return");
    let ssh = host.display("#{tmate_ssh}");
    assert_eq!(
        ssh,
        format!("ssh -p{} {}@127.0.0.1", server.target.port, host.token())
    );
    assert!(host.token_ro().starts_with("ro-"));
    assert_eq!(host.display("#{tmate_num_clients}"), "0");
    let messages = host.messages().join("\n");
    assert!(
        messages.contains("ssh session read only: ssh -p"),
        "{messages}"
    );
    assert!(messages.contains("ssh session: ssh -p"), "{messages}");
}

#[tokio::test]
async fn viewer_sees_output_and_status_line() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    host.send_keys(&["echo hello-viewer", "Enter"]);

    let viewer = Viewer::connect(&server.target, &host.token(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("hello-viewer").await;
    // The window is briefly named "[tmux]" while tmate shows its tips.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        let status = viewer.status_row().await;
        if status.contains("0:") && status.contains("*") && !status.contains("[tmux]") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "status row was {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(status.contains("0:"), "{status}");

    // The host learns about the join the same way the old service told it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while host.display("#{tmate_num_clients}") != "1" && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(host.display("#{tmate_num_clients}"), "1");
    let messages = host.messages().join("\n");
    assert!(
        messages.contains("A mate has joined (127.0.0.1) -- 1 client currently connected"),
        "{messages}"
    );

    viewer.close().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while host.display("#{tmate_num_clients}") != "0" && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(host.display("#{tmate_num_clients}"), "0");
    assert!(host.messages().join("\n").contains("A mate has left"));
}

#[tokio::test]
async fn viewer_keystrokes_reach_the_host_pane() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    let viewer = Viewer::connect(&server.target, &host.token(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
    viewer.send(b"echo typed-by-viewer\r").await;
    viewer.wait_for_text("typed-by-viewer").await;
    // Special keys travel as tmux key codes, not raw bytes: Up recalls the command.
    viewer.send(b"\x1b[A").await;
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter()
                .filter(|r| r.contains("echo typed-by-viewer"))
                .count()
                >= 2
        })
        .await;
    let pane = host.run(&["capture-pane", "-p"]);
    assert!(pane.contains("typed-by-viewer"), "host pane was:\n{pane}");
}

#[tokio::test]
async fn read_only_viewer_cannot_type() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    let viewer = Viewer::connect(&server.target, &host.token_ro(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
    viewer.send(b"echo should-not-appear\r").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pane = host.run(&["capture-pane", "-p"]);
    assert!(
        !pane.contains("should-not-appear"),
        "read-only input leaked:\n{pane}"
    );
}

#[tokio::test]
async fn host_pane_follows_smallest_read_write_viewer() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    let size = || host.display("#{pane_width}x#{pane_height}");

    let mut big = Viewer::connect(&server.target, &host.token(), 120, 40)
        .await
        .unwrap();
    wait_until(|| size() == "120x39").await;
    let ro = Viewer::connect(&server.target, &host.token_ro(), 50, 10)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        size(),
        "120x39",
        "read-only viewers must not shrink the pane"
    );
    let small = Viewer::connect(&server.target, &host.token(), 100, 30)
        .await
        .unwrap();
    wait_until(|| size() == "100x29").await;
    big.resize(90, 20).await;
    wait_until(|| size() == "90x19").await;
    big.close().await;
    wait_until(|| size() == "100x29").await;
    small.close().await;
    ro.close().await;
}

#[tokio::test]
async fn unknown_tokens_are_rejected() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    assert_eq!(
        Viewer::connect(&server.target, "nope", 80, 24).await.err(),
        Some(ViewerAuth::Rejected)
    );
    let token = host.token();
    host.kill();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        Viewer::connect(&server.target, &token, 80, 24).await.err(),
        Some(ViewerAuth::Rejected),
        "token must die with its session"
    );
}

#[tokio::test]
async fn authorized_keys_gate_viewers() {
    require_tmate!();
    let server = NewServer::start();
    let dir = tempfile::tempdir().unwrap();
    let allowed =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let other =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let keys_file = dir.path().join("authorized_keys");
    std::fs::write(
        &keys_file,
        allowed.public_key().to_openssh().unwrap() + "\n",
    )
    .unwrap();
    let host = Host::start_with_conf(
        &server.target,
        &format!("set -g tmate-authorized-keys {}", keys_file.display()),
    );
    assert!(host.prepare());
    let token = host.token();

    assert_eq!(
        Viewer::connect(&server.target, &token, 80, 24).await.err(),
        Some(ViewerAuth::Rejected)
    );
    assert_eq!(
        Viewer::connect_with_key(&server.target, &token, Some(other), 80, 24)
            .await
            .err(),
        Some(ViewerAuth::Rejected)
    );
    let viewer = Viewer::connect_with_key(&server.target, &token, Some(allowed), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
}

#[tokio::test]
async fn host_exit_ends_viewers() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    let viewer = Viewer::connect(&server.target, &host.token(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
    host.kill();
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter().any(|r| r.contains("session ended"))
        })
        .await;
}

#[tokio::test]
async fn late_viewer_gets_the_current_screen() {
    require_tmate!();
    let server = NewServer::start();
    let host = Host::start(&server.target);
    assert!(host.prepare());
    host.send_keys(&["printf 'line-%s\\n' one two three", "Enter"]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let late = Viewer::connect(&server.target, &host.token(), 80, 24)
        .await
        .unwrap();
    let rows = late.wait_for_text("line-three").await;
    let joined = rows.join("\n");
    assert!(
        joined.contains("line-one") && joined.contains("line-two"),
        "{joined}"
    );
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "condition never became true"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The viewer command prompt. Intentionally not a parity test: the old
/// server forwarded `command-prompt` to the host, where it failed for lack
/// of a client, so viewers of the old server never got a working prompt.
#[tokio::test]
async fn viewer_command_prompt_works() {
    require_tmate!();
    let server = NewServer::start();

    let host = Host::start(&server.target);
    assert!(host.prepare());
    let viewer = Viewer::connect(&server.target, &host.token(), 80, 24)
        .await
        .unwrap();
    viewer.wait_for_text("$").await;
    viewer.send(b"\x02:").await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !viewer.status_row().await.starts_with(':') && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let prompt = viewer.status_row().await;
    viewer.send(b"no-such-command\r").await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut message = String::new();
    while std::time::Instant::now() < deadline {
        let row = viewer.status_row().await;
        if row.to_lowercase().contains("command") && !row.starts_with(':') {
            message = row;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    viewer.send(b"\x02:").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second_prompt = viewer.status_row().await;
    viewer.send(b"rename-window renamed\r").await;
    let renamed = wait_until_or_timeout(|| host.display("#{window_name}") == "renamed").await;
    let status_after = viewer.status_row().await;
    viewer.close().await;
    assert_eq!(prompt, ":");
    assert_eq!(message, "Unknown command: no-such-command");
    assert_eq!(second_prompt, ":");
    assert!(renamed);
    assert_eq!(status_after, "0:renamed*");
}

async fn wait_until_or_timeout(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        if std::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}
