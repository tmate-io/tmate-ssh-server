//! The accept loop: what happens to a TCP connection before and around the
//! SSH transport. Mirrors `tmate_ssh_server_main` and `client_bootstrap` in
//! the old server:
//!
//! - with `-x`, a PROXY protocol v1 line is read first and its source
//!   address becomes the peer address the gateway logs and shows in
//!   "A mate has joined" notices;
//! - a connection has `GRACE_PERIOD` from accept to pick a role (the host
//!   subsystem, a viewer shell, or an exec request); otherwise it is closed.
//!   The old server armed `alarm(TMATE_SSH_GRACE_PERIOD)` for the same
//!   purpose. Once a role is picked only the SSH keepalive watches the link.
//!
//! Every stream is wrapped in a `Cuttable` before russh sees it, so the
//! connection can be ended from outside the session loop (`cut.rs`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::Disconnect;
use russh::server::{Config, Server, run_stream};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::cut::Cuttable;
use crate::gateway::{DISCONNECT_GRACE, Gateway};
use crate::proxy;

/// `TMATE_SSH_GRACE_PERIOD`: seconds from accept to a role.
pub const GRACE_PERIOD: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct Options {
    /// Expect a PROXY protocol v1 header before the SSH banner.
    pub proxy_protocol: bool,
    pub grace_period: Duration,
}

/// Accepts connections forever. Only a failing `accept` ends it.
pub async fn serve(
    gateway: Gateway,
    config: Arc<Config>,
    listener: TcpListener,
    options: Options,
) -> std::io::Result<()> {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) if transient_accept_error(&e) => {
                warn!(error = %e, "accept failed; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        tokio::spawn(connection(
            gateway.clone(),
            config.clone(),
            stream,
            addr,
            options.clone(),
        ));
    }
}

/// Errors `accept(2)` reports for one connection or a passing resource
/// shortage, as opposed to a dead listener.
fn transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) || matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

async fn connection(
    mut gateway: Gateway,
    config: Arc<Config>,
    mut stream: TcpStream,
    addr: SocketAddr,
    options: Options,
) {
    let deadline = Instant::now() + options.grace_period;

    let peer = if options.proxy_protocol {
        match tokio::time::timeout_at(deadline, proxy::read_header(&mut stream)).await {
            Ok(Ok(header)) => {
                debug!(socket = %addr, ?header, "proxy header");
                header.source().unwrap_or(addr)
            }
            Ok(Err(e)) => {
                warn!(socket = %addr, error = %e, "invalid PROXY header; load balancer misconfigured?");
                return;
            }
            Err(_) => {
                warn!(socket = %addr, "no PROXY header within the grace period");
                return;
            }
        }
    } else {
        addr
    };

    if config.nodelay
        && let Err(e) = stream.set_nodelay(true)
    {
        warn!(%peer, error = %e, "set_nodelay failed");
    }

    let (stream, cut) = Cuttable::new(stream);
    let mut handler = gateway.new_client(Some(peer));
    handler.cut = cut.clone();
    let mut role_chosen = handler.role_chosen.subscribe();

    // `run_stream` waits for the client's banner with no timeout of its own
    // (`inactivity_timeout` is off so idle sessions live on).
    let mut session =
        match tokio::time::timeout_at(deadline, run_stream(config, stream, handler)).await {
            Ok(Ok(session)) => session,
            Ok(Err(e)) => {
                debug!(%peer, error = %e, "connection setup failed");
                return;
            }
            Err(_) => {
                info!(%peer, "grace period passed before the SSH banner; closing");
                return;
            }
        };
    let handle = session.handle();

    tokio::select! {
        result = &mut session => {
            finish(peer, result);
            return;
        }
        waited = tokio::time::timeout_at(deadline, async {
            // Mapped to a bool so the watch guard is not held across awaits.
            role_chosen.wait_for(|chosen| *chosen).await.is_ok()
        }) => {
            match waited {
                // Role picked, or the handler is already gone: nothing to do.
                Ok(_) => {}
                Err(_) => {
                    info!(%peer, seconds = options.grace_period.as_secs(), "grace period passed without a role; closing");
                    // The disconnect is queued behind the session's other
                    // output and the client may never close its side; the
                    // cut bounds both.
                    cut.cut_after(DISCONNECT_GRACE);
                    let _ = handle
                        .disconnect(Disconnect::ByApplication, "connection grace period passed".into(), "".into())
                        .await;
                }
            }
        }
    }
    finish(peer, session.await);
}

fn finish(peer: SocketAddr, result: Result<(), russh::Error>) {
    match result {
        Ok(()) => debug!(%peer, "connection closed"),
        Err(e) => debug!(%peer, error = %e, "connection ended with error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_errors_do_not_stop_the_loop() {
        assert!(transient_accept_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionAborted
        )));
        assert!(transient_accept_error(&std::io::Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!transient_accept_error(&std::io::Error::from_raw_os_error(
            libc::EBADF
        )));
        assert!(!transient_accept_error(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
    }

    #[test]
    fn grace_period_matches_the_old_server() {
        assert_eq!(GRACE_PERIOD, Duration::from_secs(20));
    }
}
