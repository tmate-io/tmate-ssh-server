//! Regression guard for viewer typing around prefix bindings.
//!
//! It repeats the `viewer_prefix_bindings` parity sequence many times from
//! several viewers at once, with the typed command delivered whole, in two
//! writes and byte by byte: prefix+new-window, previous-window, send-prefix,
//! then `echo <marker>\r`. Every step is checked on the host, so a dropped
//! or misinterpreted key is caught.
//!
//! The bug this guards against: a key arriving within `assume-paste-time`
//! of the prefix was treated as pasted text and forwarded literally, so the
//! binding after the prefix (`C-b c` etc.) was silently dropped. That shows
//! up here as a window count that never changes (hard failure below).
//!
//! The text-after-send-prefix check is retried a few times. Typing a line
//! immediately after creating and switching windows occasionally has its
//! tail routed to the wrong window by the real tmate 2.4.0 host itself (the
//! server forwards every key in order, with no pane target, exactly as the
//! old C server did); a resend to the now-stable window lands. The binding
//! checks, not this one, are what catch a server-side key-handling
//! regression. Skipped when `tmate` is not installed.

mod support;

use std::time::{Duration, Instant};

use support::{Host, NewServer, Target, Viewer};

/// Iterations per viewer; `KEYS_STRESS_ITERS` overrides it. Kept modest so
/// the whole guard runs well under a minute even under `--test-threads=2`.
fn iterations() -> usize {
    std::env::var("KEYS_STRESS_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// Number of concurrent host+viewer pairs.
const VIEWERS: usize = 3;

#[derive(Clone, Copy, Debug)]
enum Chunking {
    Whole,
    Halves,
    Bytes,
}

impl Chunking {
    fn for_iteration(i: usize) -> Chunking {
        match i % 3 {
            0 => Chunking::Whole,
            1 => Chunking::Halves,
            _ => Chunking::Bytes,
        }
    }
}

async fn send_chunked(viewer: &Viewer, text: &[u8], how: Chunking) {
    match how {
        Chunking::Whole => viewer.send(text).await,
        Chunking::Halves => {
            let (a, b) = text.split_at(text.len() / 2);
            viewer.send(a).await;
            viewer.send(b).await;
        }
        Chunking::Bytes => {
            for b in text {
                viewer.send(std::slice::from_ref(b)).await;
            }
        }
    }
}

/// Waits up to `timeout` for `cond`; false on timeout, never panics, so the
/// caller can report both sides of a mismatch.
async fn wait(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !cond() {
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

async fn viewer_shows(viewer: &Viewer, text: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if viewer.pane_rows().await.iter().any(|r| r.contains(text)) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One viewer running the scenario `iterations()` times. Returns the
/// failures it saw, each with both screens.
async fn run_viewer(target: Target, slot: usize) -> Vec<String> {
    let host = Host::start(&target);
    assert!(host.prepare(), "viewer {slot}: host never became ready");
    let viewer = Viewer::connect(&target, &host.token(), 80, 24)
        .await
        .unwrap();
    assert!(
        viewer_shows(&viewer, "$", Duration::from_secs(10)).await,
        "viewer {slot}: no prompt"
    );
    let mut failures = Vec::new();
    let secs = Duration::from_secs;

    for i in 0..iterations() {
        let how = Chunking::for_iteration(i + slot);
        let marker = format!("after-prefix-{slot}-{i}");
        let fail = |what: &str, viewer_rows: Vec<String>, pane: String| {
            format!(
                "viewer {slot} iteration {i} ({how:?}): {what}\n--- viewer screen ---\n{}\n--- host pane ---\n{pane}\n",
                viewer_rows.join("\n")
            )
        };

        // prefix + new-window. If the command key is wrongly treated as
        // paste, the window count never changes: that is the regression.
        viewer.send(b"\x02c").await;
        if !wait(secs(10), || host.display("#{session_windows}") == "2").await {
            failures.push(fail(
                "new-window never happened (prefix binding dropped?)",
                viewer.pane_rows().await,
                host.run(&["capture-pane", "-p"]),
            ));
            break;
        }
        // previous-window, back to window 0.
        viewer.send(b"\x02p").await;
        if !wait(secs(10), || host.display("#{window_index}") == "0").await {
            failures.push(fail(
                "previous-window never happened (prefix binding dropped?)",
                viewer.pane_rows().await,
                host.run(&["capture-pane", "-p"]),
            ));
            break;
        }

        // send-prefix (C-b reaches the shell, harmless), then type a command
        // and confirm it reaches the host pane. Retried to absorb the
        // host-side window-routing race described in the module comment.
        viewer.send(b"\x02\x02").await;
        let mut reached = false;
        for attempt in 0..4 {
            send_chunked(&viewer, format!("echo {marker}\r").as_bytes(), how).await;
            let on_viewer = viewer_shows(&viewer, &marker, secs(3)).await;
            let on_host = wait(secs(3), || {
                host.run(&["capture-pane", "-p"]).contains(&marker)
            })
            .await;
            if on_viewer && on_host {
                reached = true;
                break;
            }
            if attempt < 3 {
                // Clear whatever partial line is sitting there and retry.
                viewer.send(b"\x15").await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        if !reached {
            failures.push(fail(
                "typed text never reached the host pane",
                viewer.pane_rows().await,
                host.run(&["capture-pane", "-p"]),
            ));
        }

        // Back to a single window so the next iteration starts clean.
        host.run(&["kill-window", "-t", ":1"]);
        if !wait(secs(10), || host.display("#{session_windows}") == "1").await {
            failures.push(fail(
                "kill-window never took effect",
                viewer.pane_rows().await,
                host.run(&["capture-pane", "-p"]),
            ));
            break;
        }
        if i % 4 == 3 {
            // Keep the markers from scrolling out of the captured pane.
            viewer.send(b"clear\r").await;
            wait(secs(5), || {
                host.run(&["capture-pane", "-p"])
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count()
                    <= 1
            })
            .await;
        }
    }
    viewer.close().await;
    failures
}

#[tokio::test(flavor = "multi_thread")]
async fn typing_after_prefix_bindings_never_loses_input() {
    if support::tmate_binary().is_none() {
        eprintln!("skipping: tmate not in PATH");
        return;
    }
    let server = NewServer::start();
    let mut tasks = Vec::new();
    for slot in 0..VIEWERS {
        let target = server.target.clone();
        tasks.push(tokio::spawn(run_viewer(target, slot)));
    }
    let mut failures = Vec::new();
    for task in tasks {
        failures.extend(task.await.expect("viewer task panicked"));
    }
    assert!(
        failures.is_empty(),
        "{} of {} sequences failed:\n{}",
        failures.len(),
        VIEWERS * iterations(),
        failures.join("\n")
    );
}
