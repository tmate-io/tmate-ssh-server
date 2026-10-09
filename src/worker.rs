//! The session worker: `tmate-server-rs --worker`, started by the gateway
//! with its end of a socketpair as fd 3. It locks itself down
//! (`sandbox.rs`), reports how far it got, and then runs one `Driver` fed
//! by the frames the gateway forwards (`wire.rs`). A `current_thread`
//! runtime keeps the system calls it needs to a minimum.

use std::os::fd::FromRawFd;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::keys::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::driver::{Advertised, Control, Driver};
use crate::hub::{self, Payload, Peer, ViewerId};
use crate::sandbox::{self, SandboxMode};
use crate::session::Tokens;
use crate::wire::{CHUNK, Framer, ToGateway, ToWorker};

/// The descriptor the gateway hands us.
pub const SOCKET_FD: i32 = 3;

type Out = mpsc::UnboundedSender<Vec<u8>>;

pub fn main(sandbox: SandboxMode) -> ExitCode {
    let span = tracing::info_span!("worker", pid = std::process::id());
    let _enter = span.enter();

    // SAFETY: fd 3 is the socket the gateway dup2'd there before exec; we
    // are its only owner from here on.
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(SOCKET_FD) };
    if let Err(e) = socket.set_nonblocking(true) {
        error!(error = %e, "fd 3 is not a usable socket; was the worker started by the gateway?");
        return ExitCode::from(2);
    }

    let (summary, level) = if sandbox == SandboxMode::Off {
        ("sandbox off".to_string(), 0)
    } else {
        let report = sandbox::lockdown(SOCKET_FD);
        report.log();
        let level = report.level();
        if sandbox == SandboxMode::Require && level < 2 {
            error!(summary = %report.summary(), "sandbox incomplete and --sandbox require is set; refusing to run");
            return ExitCode::from(3);
        }
        (report.summary(), level)
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "cannot start the worker runtime");
            return ExitCode::from(4);
        }
    };
    runtime.block_on(run(socket, summary, level));
    ExitCode::SUCCESS
}

/// Where a worker-side `Peer`'s bytes go.
#[derive(Clone, Copy)]
enum Target {
    Host(u64),
    Viewer(ViewerId),
}

/// A peer whose output becomes frames for the gateway.
fn peer_for(out: &Out, target: Target, tasks: &mut JoinSet<()>) -> Peer {
    let (peer, mut rx) = Peer::new();
    let out = out.clone();
    tasks.spawn(async move {
        while let Some(payload) = rx.recv().await {
            match payload {
                Payload::Data(data) => {
                    for chunk in data.chunks(CHUNK) {
                        let msg = match target {
                            Target::Host(epoch) => ToGateway::ToHost {
                                epoch,
                                data: chunk.to_vec(),
                            },
                            Target::Viewer(id) => ToGateway::ToViewer {
                                id,
                                data: chunk.to_vec(),
                            },
                        };
                        if out.send(msg.encode()).is_err() {
                            return;
                        }
                    }
                }
                Payload::Close => {
                    let msg = match target {
                        Target::Host(epoch) => ToGateway::CloseHost { epoch },
                        Target::Viewer(id) => ToGateway::CloseViewer(id),
                    };
                    let _ = out.send(msg.encode());
                    return;
                }
            }
        }
    });
    peer
}

/// `Control` that asks the gateway.
struct WorkerControl {
    out: Out,
    /// Bytes that followed a RECONNECT, kept until the gateway answers.
    pending_rest: Arc<Mutex<Option<Vec<u8>>>>,
    /// Signed by the gateway for the current tokens.
    reconnection_data: Arc<Mutex<String>>,
}

impl Control for WorkerControl {
    fn register(&self, tokens: &Tokens) {
        let _ = self.out.send(ToGateway::Register(tokens.clone()).encode());
    }

    fn unregister(&self, tokens: &Tokens) {
        let _ = self
            .out
            .send(ToGateway::Unregister(tokens.clone()).encode());
    }

    fn authorized_keys(&self, enabled: bool, keys: &[PublicKey]) {
        let keys = keys.iter().filter_map(|k| k.to_openssh().ok()).collect();
        let _ = self
            .out
            .send(ToGateway::AuthorizedKeys { enabled, keys }.encode());
    }

    fn reconnection_data(&self, _tokens: &Tokens) -> String {
        self.reconnection_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn reconnect(&self, data: String, rest: Vec<u8>, client_version: String) {
        *self
            .pending_rest
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(rest.clone());
        let _ = self.out.send(
            ToGateway::Reconnect {
                data,
                rest,
                client_version,
            }
            .encode(),
        );
    }
}

struct Session {
    driver: Arc<Mutex<Driver>>,
    pending_rest: Arc<Mutex<Option<Vec<u8>>>>,
    reconnection_data: Arc<Mutex<String>>,
}

async fn run(socket: std::os::unix::net::UnixStream, summary: String, level: u8) {
    let socket = match tokio::net::UnixStream::from_std(socket) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "cannot register the gateway socket");
            return;
        }
    };
    let (mut rd, mut wr) = socket.into_split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    let _ = out.send(
        ToGateway::Ready {
            sandbox: summary,
            level,
        }
        .encode(),
    );

    let mut tasks = JoinSet::new();
    let mut session: Option<Session> = None;
    let mut framer = Framer::new();
    let mut buf = vec![0u8; 64 * 1024];
    'read: loop {
        let n = match rd.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!(error = %e, "gateway socket closed");
                break;
            }
        };
        framer.feed(&buf[..n]);
        loop {
            let payload = match framer.next_frame() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    error!(error = %e, "bad frame from the gateway");
                    break 'read;
                }
            };
            let msg = match ToWorker::decode(&payload) {
                Ok(m) => m,
                Err(e) => {
                    error!(error = %e, "bad message from the gateway");
                    break 'read;
                }
            };
            if !handle(msg, &mut session, &out, &mut tasks) {
                break 'read;
            }
        }
    }

    // The host is gone one way or another: end the session, let the
    // peers forward their last bytes, then flush and exit.
    if let Some(s) = session.take() {
        s.driver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .host_gone();
        drop(s);
    }
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .is_err()
    {
        warn!("some output was still queued when the worker exited");
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    debug!("worker done");
}

/// Applies one message; false ends the worker.
fn handle(
    msg: ToWorker,
    session: &mut Option<Session>,
    out: &Out,
    tasks: &mut JoinSet<()>,
) -> bool {
    match (msg, session.as_ref()) {
        (
            ToWorker::Hello {
                peer_ip,
                advertised_host,
                advertised_port,
                keys_required,
                tokens,
                reconnection_data,
            },
            None,
        ) => {
            let pending_rest = Arc::new(Mutex::new(None));
            let reconnection_data = Arc::new(Mutex::new(reconnection_data));
            let control = WorkerControl {
                out: out.clone(),
                pending_rest: pending_rest.clone(),
                reconnection_data: reconnection_data.clone(),
            };
            let host = peer_for(out, Target::Host(0), tasks);
            let driver = Driver::new(
                tokens,
                keys_required,
                peer_ip,
                Arc::new(Advertised {
                    host: advertised_host,
                    port: advertised_port,
                }),
                host,
                Box::new(control),
            );
            info!("session worker started");
            *session = Some(Session {
                driver: Arc::new(Mutex::new(driver)),
                pending_rest,
                reconnection_data,
            });
            true
        }
        (ToWorker::Hello { .. }, Some(_)) => {
            error!("second Hello from the gateway");
            false
        }
        (_, None) => {
            error!("message before Hello");
            false
        }
        (ToWorker::HostData(data), Some(s)) => {
            s.driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .host_data(&data);
            true
        }
        (ToWorker::HostGone, Some(_)) => false,
        (
            ToWorker::ViewerAttach {
                id,
                ip,
                access,
                size,
            },
            Some(s),
        ) => {
            let peer = peer_for(out, Target::Viewer(id), tasks);
            s.driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .attach_viewer(id, peer, access, &ip, size);
            true
        }
        (ToWorker::ViewerInput { id, data }, Some(s)) => {
            let held = s
                .driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .viewer_input(id, &data);
            if let Some(generation) = held {
                // A lone ESC might be the start of a sequence split across
                // packets; after the delay it is sent as a plain Escape.
                let driver = s.driver.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(hub::ESC_FLUSH_DELAY).await;
                    driver
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .flush_viewer(id, generation);
                });
            }
            true
        }
        (ToWorker::ViewerResize { id, size }, Some(s)) => {
            s.driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .resize_viewer(id, size);
            true
        }
        (ToWorker::ViewerDetach(id), Some(s)) => {
            s.driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .detach_viewer(id);
            true
        }
        (
            ToWorker::ReconnectResult {
                tokens,
                reconnection_data,
            },
            Some(s),
        ) => {
            let rest = s
                .pending_rest
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .unwrap_or_default();
            let mut driver = s.driver.lock().unwrap_or_else(PoisonError::into_inner);
            match tokens {
                Some(t) => {
                    *s.reconnection_data
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = reconnection_data;
                    driver.reconnect_fresh(t, rest);
                }
                None => driver.reconnect_rejected(rest),
            }
            true
        }
        (
            ToWorker::HostAdopted {
                epoch,
                peer_ip,
                client_version,
            },
            Some(s),
        ) => {
            let host = peer_for(out, Target::Host(epoch), tasks);
            s.driver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .adopt_host(host, peer_ip, client_version, Vec::new());
            true
        }
    }
}
