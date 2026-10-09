//! Parity tests: the same scenario is run against the old C server (the
//! reference, reached through `TMATE_REF_ADDR`/`TMATE_REF_FINGERPRINT`) and
//! the Rust server, and everything observable is compared. Skipped when no
//! reference server is configured.
//!
//! Start the reference with the old repo's Dockerfile, e.g.
//! `docker run --privileged -p 2201:2200 -e SSH_KEYS_PATH=/keys -e SSH_HOSTNAME=127.0.0.1 -e SSH_PORT_ADVERTISE=2201 -v $KEYS:/keys tmate-ssh-server-old`
//! and export `TMATE_REF_ADDR=127.0.0.1:2201` plus the key's SHA256 fingerprint.

mod support;

use std::time::Duration;

use support::{Host, NewServer, Target, Viewer};

macro_rules! require_reference {
    () => {
        match (support::tmate_binary(), support::reference_target()) {
            (Some(_), Some(r)) => r,
            _ => {
                eprintln!("skipping: needs tmate in PATH and TMATE_REF_ADDR/TMATE_REF_FINGERPRINT");
                return;
            }
        }
    };
}

/// What a host sees right after the handshake, with the parts that legitimately
/// differ between servers (token, port) normalised.
#[derive(Debug, PartialEq)]
struct HandshakeView {
    ssh_shape: String,
    ssh_ro_shape: String,
    num_clients: String,
    notices: Vec<String>,
}

fn shape(link: &str) -> String {
    // "ssh -p2201 TOKEN@127.0.0.1" -> "ssh -pPORT TOKEN@127.0.0.1"
    let mut out = String::new();
    for word in link.split(' ') {
        if let Some(rest) = word.strip_prefix("-p") {
            out.push_str(if rest.chars().all(|c| c.is_ascii_digit()) {
                "-pPORT "
            } else {
                word
            });
            if !rest.chars().all(|c| c.is_ascii_digit()) {
                out.push(' ');
            }
        } else if let Some((token, host)) = word.split_once('@') {
            let kind = if token.starts_with("ro-") {
                "RO-TOKEN"
            } else {
                "TOKEN"
            };
            out.push_str(&format!("{kind}@{host} "));
        } else {
            out.push_str(word);
            out.push(' ');
        }
    }
    out.trim_end().to_string()
}

/// Notices the host shows, minus tmate's own local tips and anything token-specific.
fn interesting_notices(messages: &[String]) -> Vec<String> {
    messages
        .iter()
        .filter(|m| m.contains("session") || m.contains("mate has") || m.contains("Note:"))
        .map(|m| {
            let m = m.split_once("[tmate] ").map(|(_, rest)| rest).unwrap_or(m); // drop the timestamp
            shape(m)
        })
        .collect()
}

/// Blanks the fields only a backend-equipped server produces when the
/// reference has no backend, so the comparison covers what both can do.
/// Those features have their own tests in `tests/live.rs`.
fn mask_backend_features<T: Default>(reference: &Target, field: &mut T) {
    if !reference.has_backend_features {
        *field = T::default();
    }
}

fn handshake(target: &Target) -> HandshakeView {
    let host = Host::start(target);
    assert!(
        host.prepare(),
        "{target:?}: wait tmate-ready did not return"
    );
    HandshakeView {
        ssh_shape: shape(&host.display("#{tmate_ssh}")),
        ssh_ro_shape: shape(&host.display("#{tmate_ssh_ro}")),
        num_clients: host.display("#{tmate_num_clients}"),
        notices: interesting_notices(&host.messages()),
    }
}

#[tokio::test]
async fn handshake_matches_reference() {
    let reference = require_reference!();
    let server = NewServer::start();
    let mut ours = handshake(&server.target);
    let mut theirs = handshake(&reference);
    mask_backend_features(&reference, &mut ours.num_clients);
    mask_backend_features(&reference, &mut theirs.num_clients);
    assert_eq!(ours, theirs);
}

/// The viewer's screen after a fixed script, plus host-side effects.
#[derive(Debug, PartialEq)]
struct ViewingView {
    pane_after_output: Vec<String>,
    status_left: String,
    num_clients_with_viewer: String,
    pane_after_typing: String,
    pane_size_after_resize: String,
    read_only_leaked: bool,
    join_notices: Vec<String>,
}

async fn viewing(target: &Target) -> ViewingView {
    let host = Host::start(target);
    assert!(host.prepare());
    host.send_keys(&["printf 'alpha\\nbeta\\n'", "Enter"]);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut viewer = Viewer::connect(target, &host.token(), 80, 24)
        .await
        .unwrap();
    let pane_after_output = viewer.wait_for_text("beta").await;
    let status = viewer.status_row().await;
    let status_left = status.split("  ").next().unwrap_or("").to_string();
    if target.has_backend_features {
        wait_until(|| host.display("#{tmate_num_clients}") == "1").await;
    }
    let num_clients_with_viewer = host.display("#{tmate_num_clients}");

    viewer.send(b"echo typed\r").await;
    viewer.wait_for_text("typed").await;
    let pane_after_typing = host.run(&["capture-pane", "-p"]).trim_end().to_string();

    viewer.resize(100, 30).await;
    wait_until(|| host.display("#{pane_width}x#{pane_height}") == "100x29").await;
    let pane_size_after_resize = host.display("#{pane_width}x#{pane_height}");

    let ro = Viewer::connect(target, &host.token_ro(), 80, 24)
        .await
        .unwrap();
    ro.wait_for_text("typed").await;
    ro.send(b"echo leaked\r").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let read_only_leaked = host.run(&["capture-pane", "-p"]).contains("leaked");
    ro.close().await;
    viewer.close().await;
    if target.has_backend_features {
        wait_until(|| host.display("#{tmate_num_clients}") == "0").await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Invalid tokens are not compared: the old server accepted SSH auth and
    // printed "Invalid session token" afterwards, we reject at auth (see PLAN.md).
    ViewingView {
        pane_after_output,
        status_left,
        num_clients_with_viewer,
        pane_after_typing,
        pane_size_after_resize,
        read_only_leaked,
        join_notices: interesting_notices(&host.messages())
            .into_iter()
            .filter(|m| m.contains("mate"))
            .collect(),
    }
}

#[tokio::test]
async fn viewing_matches_reference() {
    let reference = require_reference!();
    let server = NewServer::start();
    let mut ours = viewing(&server.target).await;
    let mut theirs = viewing(&reference).await;
    for view in [&mut ours, &mut theirs] {
        mask_backend_features(&reference, &mut view.num_clients_with_viewer);
        mask_backend_features(&reference, &mut view.join_notices);
    }
    assert_eq!(ours, theirs);
}

/// Colours, attributes, wide characters and the alternate screen, rendered by
/// each server and read back through the same emulator.
async fn rendering(target: &Target) -> Vec<String> {
    let host = Host::start(target);
    assert!(host.prepare());
    let viewer = attach(target, &host, 80, 24).await;
    host.send_keys(&[
        "printf '\\033[1;31mred-bold\\033[0m \\033[4munder\\033[0m \\033[7mrev\\033[0m 日本語 \\033[38;5;33mc256\\033[0m\\n'",
        "Enter",
    ]);
    viewer.wait_for_text("c256").await;
    host.send_keys(&[
        "printf '\\033[?1049h\\033[Halt-screen\\033[?1049l'; echo back",
        "Enter",
    ]);
    viewer.wait_for_text("back").await;
    let rows = viewer.pane_rows().await;
    viewer.close().await;
    rows
}

#[tokio::test]
async fn rendering_matches_reference() {
    let reference = require_reference!();
    let server = NewServer::start();
    assert_eq!(rendering(&server.target).await, rendering(&reference).await);
}

/// Connects a read-write viewer and waits until the host pane has taken the
/// viewer's size and shows a prompt. Output produced before the resize lands
/// would be reflowed at a run-dependent point, which makes history counts
/// (and so copy-mode indicators) differ between runs.
async fn attach(target: &Target, host: &Host, cols: u16, rows: u16) -> Viewer {
    let viewer = Viewer::connect(target, &host.token(), cols, rows)
        .await
        .unwrap();
    let want = format!("{cols}x{}", rows - 1);
    wait_until(|| host.display("#{pane_width}x#{pane_height}") == want).await;
    viewer.wait_for_text("$").await;
    // The resize makes the shell redraw its prompt a moment later; let that
    // land, then start from a clean pane so both servers mirror the same
    // stream from here on.
    tokio::time::sleep(Duration::from_millis(400)).await;
    host.clear();
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter().filter(|r| !r.is_empty()).count() == 1
        })
        .await;
    viewer
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

/// Runs `scenario` against both servers and asserts identical observations.
macro_rules! parity_scenario {
    ($name:ident, $scenario:ident) => {
        #[tokio::test]
        async fn $name() {
            let reference = require_reference!();
            let server = NewServer::start();
            let ours = $scenario(&server.target).await;
            let theirs = $scenario(&reference).await;
            assert_eq!(ours, theirs, "left = Rust server, right = old server");
        }
    };
}

/// Several windows and a split: what the viewer sees, with the status row.
async fn windows_and_panes(target: &Target) -> Vec<Vec<String>> {
    let host = Host::start(target);
    assert!(host.prepare());
    let viewer = attach(target, &host, 80, 24).await;
    let mut shots = Vec::new();

    host.run(&["new-window", "bash", "--norc", "--noprofile"]);
    host.run(&["split-window", "-h", "bash", "--norc", "--noprofile"]);
    host.send_keys(&["echo pane-two", "Enter"]);
    viewer.wait_for_text("pane-two").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    shots.push(viewer.rows().await);

    host.run(&["select-pane", "-L"]);
    host.send_keys(&["echo pane-one", "Enter"]);
    viewer.wait_for_text("pane-one").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    shots.push(viewer.rows().await);

    host.run(&["select-window", "-t", "0"]);
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            !rows.iter().any(|r| r.contains("pane-one"))
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    shots.push(viewer.rows().await);
    viewer.close().await;
    shots
}
parity_scenario!(windows_and_panes_match_reference, windows_and_panes);

/// Prefix bindings typed by a viewer: C-b c, C-b n, C-b d.
async fn viewer_prefix_bindings(target: &Target) -> Vec<String> {
    let host = Host::start(target);
    assert!(host.prepare());
    let viewer = attach(target, &host, 80, 24).await;
    let mut log = Vec::new();

    viewer.send(b"\x02c").await; // prefix, new-window
    wait_until(|| host.display("#{session_windows}") == "2").await;
    log.push(format!("windows={}", host.display("#{session_windows}")));
    viewer.send(b"\x02p").await; // previous-window
    wait_until(|| host.display("#{window_index}") == "0").await;
    log.push(format!("window={}", host.display("#{window_index}")));
    viewer.send(b"\x02\x02").await; // send-prefix: C-b reaches the shell, harmless
    // tmate 2.4.0 occasionally routes the tail of a line typed right after a
    // window switch to the other window; both servers inherit that, so the
    // typed line is retried a few times (as tests/keys_stress.rs does).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut typed = false;
    for _ in 0..3 {
        viewer.send(b"echo after-prefix\r").await;
        if wait_until_or_timeout(|| host.run(&["capture-pane", "-p"]).contains("after-prefix"))
            .await
        {
            typed = true;
            break;
        }
        viewer.send(b"\x15").await; // C-u: discard whatever is on the line
    }
    assert!(typed, "typed line never reached the pane");
    viewer.wait_for_text("after-prefix").await;
    log.push("typed after send-prefix".into());
    viewer.send(b"\x02d").await; // detach-client
    tokio::time::sleep(Duration::from_millis(500)).await;
    if target.has_backend_features {
        wait_until(|| host.display("#{tmate_num_clients}") == "0").await;
    }
    log.push("detached".into());
    log
}
parity_scenario!(
    viewer_prefix_bindings_match_reference,
    viewer_prefix_bindings
);

/// Copy mode entered on the host is mirrored to viewers with its indicator.
async fn copy_mode_view(target: &Target) -> Vec<Vec<String>> {
    let host = Host::start(target);
    assert!(host.prepare());
    let viewer = attach(target, &host, 80, 24).await;
    host.send_keys(&["seq 1 40", "Enter"]);
    viewer.wait_for_text("40").await;
    host.run(&["copy-mode", "-u"]);
    viewer
        .wait_for(Duration::from_secs(10), |rows| {
            rows.iter().any(|r| r.contains('['))
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut in_mode = viewer.rows().await;
    // The `[0/N]` indicator is the server's history size. Each server must
    // agree with its own host (tests/replay.rs proves identical streams give
    // identical N on both servers), but the two hosts' streams differ by a
    // line depending on when the shell echoed `clear`, so N is checked per
    // server here and masked in the cross-server comparison.
    let hsize = host.display("#{history_size}");
    let indicator = format!("[0/{hsize}]");
    assert!(
        in_mode[0].contains(&indicator),
        "server history ({}) disagrees with its host's history_size {hsize}",
        in_mode[0]
    );
    in_mode[0] = in_mode[0].replace(&indicator, "[0/H]");
    host.send_keys(&["q"]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = viewer.rows().await;
    viewer.close().await;
    vec![in_mode, after]
}
parity_scenario!(copy_mode_matches_reference, copy_mode_view);

/// Lots of output, then a late joiner: both must end on the same screen.
async fn heavy_output(target: &Target) -> Vec<Vec<String>> {
    let host = Host::start(target);
    assert!(host.prepare());
    let viewer = attach(target, &host, 80, 24).await;
    host.send_keys(&[
        "seq 1 5000 | sed 's/$/ lorem ipsum dolor sit amet/'; echo done-heavy",
        "Enter",
    ]);
    viewer.wait_for_text("done-heavy").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let late = Viewer::connect(target, &host.token(), 80, 24)
        .await
        .unwrap();
    late.wait_for_text("done-heavy").await;
    let shots = vec![viewer.pane_rows().await, late.pane_rows().await];
    viewer.close().await;
    late.close().await;
    shots
}
parity_scenario!(heavy_output_matches_reference, heavy_output);

/// Two read-write viewers of different sizes: the pane follows the smaller
/// one and both see the same content.
async fn two_viewer_sizes(target: &Target) -> Vec<Vec<String>> {
    let host = Host::start(target);
    assert!(host.prepare());
    let big = attach(target, &host, 100, 30).await;
    let small = Viewer::connect(target, &host.token(), 60, 20)
        .await
        .unwrap();
    wait_until(|| host.display("#{pane_width}x#{pane_height}") == "60x19").await;
    host.send_keys(&["clear; echo sized-$(tput cols)x$(tput lines)", "Enter"]);
    big.wait_for_text("sized-").await;
    small.wait_for_text("sized-").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let shots = vec![big.pane_rows().await, small.pane_rows().await];
    big.close().await;
    small.close().await;
    shots
}
parity_scenario!(two_viewer_sizes_match_reference, two_viewer_sizes);

/// Like `wait_until` but reports instead of panicking, with a shorter patience.
async fn wait_until_or_timeout(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !cond() {
        if std::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}
