//! The gateway's handle on one session. A `SessionHandle` offers the
//! connection handlers the same operations whether the session's `Driver`
//! runs in this process or in a sandboxed worker process reached over a
//! socketpair (`wire.rs`, `worker.rs`).
//!
//! A reconnecting host (`RECONNECT` with data this gateway signed for a
//! session still alive) does not get a session of its own: its handle
//! starts forwarding to the live session's handle, whose driver adopts the
//! new host connection. Viewers keep their handle and never notice.
//!
//! With a backend (`-w`), the handle also owns the session's TCP
//! connection to it: a writer task fed by the driver (directly, or through
//! `ToGateway::ToBackend` from a worker) and a reader task that hands the
//! backend's bytes to the driver. The driver never sees a socket.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::backend;
use crate::driver::{Advertised, Config, Control, Driver};
use crate::hub::{self, Payload, Peer, ViewerId};
use crate::limits::SessionGuard;
use crate::reconnect;
use crate::render::Size;
use crate::sandbox::SandboxMode;
use crate::session::{Access, Registry, Tokens};
use crate::wire::{Framer, ToGateway, ToWorker};

/// Where sessions run; decided once at startup.
#[derive(Debug, Clone)]
pub enum Mode {
    InProcess,
    Worker {
        exe: PathBuf,
        sandbox: SandboxMode,
        verbose: u8,
    },
}

/// What every session needs from the server.
pub struct Env {
    pub registry: Arc<Registry>,
    pub advertised: Arc<Advertised>,
    pub keys_required: bool,
    pub mode: Mode,
    /// The tmate-websocket backend every session connects to, if any.
    pub backend: Option<backend::Addr>,
    /// Where the backend expects a session's files (`SessionFiles`).
    pub sessions_dir: Option<PathBuf>,
}

/// The files the backend looks for in its `tmux_socket_path`: the old
/// server's tmux socket `<dir>/<token>` and the `<dir>/<ro-token>` symlink
/// to it. When the backend names a session or a host reconnects, it
/// renames them itself (`rename_tmux_sockets!`) before it sends
/// `CTL_RENAME_SESSION`, and crashes the session when they are missing.
/// This server has no sockets, so it leaves placeholders there and
/// removes them, under whatever name they ended up with, when the
/// session ends.
pub struct SessionFiles {
    dir: PathBuf,
}

impl SessionFiles {
    /// `/` and `.` become `=`, as the backend spells file names.
    fn path(dir: &Path, token: &str) -> PathBuf {
        dir.join(token.replace(['/', '.'], "="))
    }

    pub fn create(dir: &Path, tokens: &Tokens) -> std::io::Result<SessionFiles> {
        let rw = Self::path(dir, &tokens.rw);
        let ro = Self::path(dir, &tokens.ro);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&rw)?;
        let _ = std::fs::remove_file(&ro);
        std::os::unix::fs::symlink(rw.file_name().unwrap_or_default(), &ro)?;
        Ok(SessionFiles {
            dir: dir.to_path_buf(),
        })
    }

    pub fn remove(&self, tokens: &Tokens) {
        for token in [&tokens.rw, &tokens.ro] {
            if crate::session::is_acceptable_token(token) {
                let _ = std::fs::remove_file(Self::path(&self.dir, token));
            }
        }
    }
}

/// How long connecting to the backend may take before a session is
/// refused.
pub const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens the session's connection to the backend (`tmate_connect_to_websocket`).
pub async fn connect_backend(addr: &backend::Addr) -> std::io::Result<tokio::net::TcpStream> {
    let stream = tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((addr.host.as_str(), addr.port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// The gateway's end of a session's backend connection.
struct BackendLink {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    reader: tokio::task::JoinHandle<()>,
}

impl BackendLink {
    fn send(&self, data: Vec<u8>) {
        let _ = self.tx.send(data);
    }
}

impl Drop for BackendLink {
    fn drop(&mut self) {
        // The writer ends once the queue drains; the reader is stopped so
        // its EOF is not reported as a lost backend.
        self.reader.abort();
    }
}

/// A RECONNECT the in-process driver reported: data, what followed it,
/// the client's version.
type PendingReconnect = Arc<Mutex<Option<(String, Vec<u8>, String)>>>;

pub struct SessionHandle {
    inner: Mutex<Inner>,
    next_viewer: AtomicU64,
    /// Bumped each time a reconnecting host takes the session over, so a
    /// superseded connection's cleanup does not end the session.
    host_epoch: AtomicU64,
    registry: Arc<Registry>,
    guard: Mutex<Option<SessionGuard>>,
    /// Separate from `inner`: the driver asks for backend writes while
    /// `inner` is locked.
    backend: Mutex<Option<BackendLink>>,
    files: Mutex<Option<SessionFiles>>,
    me: Weak<SessionHandle>,
}

enum Inner {
    Local {
        driver: Driver,
        /// A RECONNECT the driver reported while this handle was locked.
        pending_reconnect: PendingReconnect,
    },
    Remote(WorkerLink),
    /// This host took over the session behind `target`; its connection
    /// is that session's host epoch `epoch`.
    Forward {
        target: Arc<SessionHandle>,
        epoch: u64,
    },
    Ended,
}

struct WorkerLink {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    tokens: Tokens,
    peer_ip: String,
    hosts: HashMap<u64, Peer>,
    viewers: HashMap<ViewerId, Peer>,
    /// `Some` once the host enabled a key list.
    auth: Option<Vec<PublicKey>>,
    pid: Option<u32>,
}

impl WorkerLink {
    fn send(&self, msg: &ToWorker) {
        let _ = self.tx.send(msg.encode());
    }
}

/// `Control` for an in-process driver. Calls arrive while the handle's
/// lock is held, so a reconnect request is parked and resolved by the
/// handle right after the driver returns.
struct LocalControl {
    handle: Weak<SessionHandle>,
    registry: Arc<Registry>,
    pending_reconnect: PendingReconnect,
}

impl Control for LocalControl {
    fn register(&self, tokens: &Tokens) {
        if let Some(h) = self.handle.upgrade()
            && !self.registry.insert(tokens, h)
        {
            tracing::warn!(token = %&tokens.rw[..tokens.rw.len().min(4)], "token already belongs to another session; not registered");
        }
    }

    fn unregister(&self, tokens: &Tokens) {
        if let Some(h) = self.handle.upgrade() {
            self.registry.remove_if(tokens, &h);
        }
    }

    fn authorized_keys(&self, _enabled: bool, _keys: &[PublicKey]) {}

    fn reconnection_data(&self, tokens: &Tokens) -> String {
        reconnect::data_for(tokens)
    }

    fn reconnect(&self, data: String, rest: Vec<u8>, client_version: String) {
        *self
            .pending_reconnect
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((data, rest, client_version));
    }

    fn backend_send(&self, data: Vec<u8>) {
        if let Some(h) = self.handle.upgrade() {
            h.backend_send(data);
        }
    }

    fn backend_close(&self) {
        if let Some(h) = self.handle.upgrade() {
            h.backend_close();
        }
    }
}

/// How a session's worker ended, for the log.
fn describe_exit(status: std::io::Result<std::process::ExitStatus>) -> String {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(s) => match (s.code(), s.signal()) {
            (Some(0), _) => "exited normally".into(),
            (Some(c), _) => format!("exited with status {c}"),
            (None, Some(libc::SIGSYS)) => {
                "killed by SIGSYS: it made a system call outside the seccomp allowlist".into()
            }
            (None, Some(libc::SIGXCPU)) => {
                "killed by SIGXCPU: it used up its CPU time limit".into()
            }
            (None, Some(sig)) => format!("killed by signal {sig}"),
            (None, None) => "ended".into(),
        },
        Err(e) => format!("wait failed: {e}"),
    }
}

impl SessionHandle {
    /// Starts a session for a host connecting from `peer_ip`. `backend` is
    /// the session's connection to the backend when the server has one.
    pub fn start(
        env: &Env,
        peer_ip: String,
        host_pubkey: Option<String>,
        host: Peer,
        guard: SessionGuard,
        backend: Option<tokio::net::TcpStream>,
    ) -> Arc<SessionHandle> {
        let tokens = Tokens::generate();
        let has_backend = backend.is_some();
        let files = env
            .sessions_dir
            .as_deref()
            .filter(|_| has_backend)
            .and_then(|dir| match SessionFiles::create(dir, &tokens) {
                Ok(files) => Some(files),
                Err(e) => {
                    warn!(peer = %peer_ip, dir = %dir.display(), error = %e, "cannot create the session files the backend expects; it will not be able to name or resume this session");
                    None
                }
            });
        Arc::new_cyclic(|me: &Weak<SessionHandle>| {
            let backend = backend.map(|stream| start_backend(me.clone(), stream, peer_ip.clone()));
            let inner = match &env.mode {
                Mode::InProcess => {
                    let pending = Arc::new(Mutex::new(None));
                    let control = LocalControl {
                        handle: me.clone(),
                        registry: env.registry.clone(),
                        pending_reconnect: pending.clone(),
                    };
                    Inner::Local {
                        driver: Driver::new(
                            Config {
                                tokens,
                                keys_required: env.keys_required,
                                peer_ip,
                                host_pubkey,
                                advertised: env.advertised.clone(),
                                backend: has_backend,
                            },
                            host,
                            Box::new(control),
                        ),
                        pending_reconnect: pending,
                    }
                }
                Mode::Worker {
                    exe,
                    sandbox,
                    verbose,
                } => match spawn_worker(exe, *sandbox, *verbose) {
                    Ok((stream, child)) => {
                        let pid = child.id();
                        let (rd, wr) = stream.into_split();
                        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                        tokio::spawn(write_frames(wr, rx));
                        tokio::spawn(read_worker(me.clone(), rd, child, peer_ip.clone()));
                        let link = WorkerLink {
                            tx,
                            tokens: tokens.clone(),
                            peer_ip: peer_ip.clone(),
                            hosts: HashMap::from([(0, host)]),
                            viewers: HashMap::new(),
                            auth: None,
                            pid,
                        };
                        link.send(&ToWorker::Hello {
                            peer_ip,
                            host_pubkey,
                            advertised_host: env.advertised.host.clone(),
                            advertised_port: env.advertised.port,
                            keys_required: env.keys_required,
                            reconnection_data: reconnect::data_for(&tokens),
                            tokens,
                            backend: has_backend,
                        });
                        Inner::Remote(link)
                    }
                    Err(e) => {
                        error!(peer = %peer_ip, error = %e, "cannot start a session worker; refusing the session");
                        host.send(Payload::Close);
                        Inner::Ended
                    }
                },
            };
            SessionHandle {
                inner: Mutex::new(inner),
                next_viewer: AtomicU64::new(1),
                host_epoch: AtomicU64::new(0),
                registry: env.registry.clone(),
                guard: Mutex::new(Some(guard)),
                backend: Mutex::new(backend),
                files: Mutex::new(files),
                me: me.clone(),
            }
        })
    }

    /// Removes the session's files under the given names. Idempotent: a
    /// backend rename unregisters the old tokens first (their files are
    /// already gone), and the session's end removes the current ones.
    fn remove_files(&self, tokens: &Tokens) {
        if let Some(files) = &*self.files.lock().unwrap_or_else(PoisonError::into_inner) {
            files.remove(tokens);
        }
    }

    fn backend_send(&self, data: Vec<u8>) {
        if let Some(link) = &*self.backend.lock().unwrap_or_else(PoisonError::into_inner) {
            link.send(data);
        }
    }

    fn backend_close(&self) {
        self.backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Bytes from the backend connection.
    fn backend_data(&self, data: &[u8]) {
        match &mut *self.lock() {
            Inner::Local { driver, .. } => driver.backend_data(data),
            Inner::Remote(l) => l.send(&ToWorker::BackendData(data.to_vec())),
            Inner::Forward { .. } | Inner::Ended => {}
        }
    }

    /// The backend connection ended on its side.
    fn backend_gone(&self) {
        match &mut *self.lock() {
            Inner::Local { driver, .. } => {
                driver.backend_gone();
                self.remove_files(driver.tokens());
                self.release_guard();
            }
            Inner::Remote(l) => l.send(&ToWorker::BackendGone),
            Inner::Forward { .. } | Inner::Ended => {}
        }
        self.backend_close();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where calls go: here, or the handle this one forwards to.
    fn forward_target(&self) -> Option<(Arc<SessionHandle>, u64)> {
        match &*self.lock() {
            Inner::Forward { target, epoch } => Some((target.clone(), *epoch)),
            _ => None,
        }
    }

    pub fn tokens(&self) -> Option<Tokens> {
        if let Some((t, _)) = self.forward_target() {
            return t.tokens();
        }
        match &*self.lock() {
            Inner::Local { driver, .. } => Some(driver.tokens().clone()),
            Inner::Remote(l) => Some(l.tokens.clone()),
            Inner::Forward { .. } | Inner::Ended => None,
        }
    }

    pub fn keys_enabled(&self) -> bool {
        if let Some((t, _)) = self.forward_target() {
            return t.keys_enabled();
        }
        match &*self.lock() {
            Inner::Local { driver, .. } => driver.hub().keys_enabled(),
            Inner::Remote(l) => l.auth.is_some(),
            Inner::Forward { .. } | Inner::Ended => false,
        }
    }

    /// Mirrors `tmate_allow_auth`: anyone without a key list, otherwise
    /// only a key whose public part is listed.
    pub fn authorize(&self, key: Option<&PublicKey>) -> bool {
        if let Some((t, _)) = self.forward_target() {
            return t.authorize(key);
        }
        match &*self.lock() {
            Inner::Local { driver, .. } => driver.hub().authorize(key),
            Inner::Remote(l) => match (&l.auth, key) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(list), Some(k)) => list.iter().any(|a| a.key_data() == k.key_data()),
            },
            Inner::Forward { .. } | Inner::Ended => false,
        }
    }

    /// Bytes from the host connection.
    pub fn host_data(self: &Arc<Self>, data: &[u8]) {
        if let Some((t, _)) = self.forward_target() {
            return t.host_data(data);
        }
        let reconnect = {
            let mut inner = self.lock();
            match &mut *inner {
                Inner::Local {
                    driver,
                    pending_reconnect,
                } => {
                    driver.host_data(data);
                    pending_reconnect
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                }
                Inner::Remote(l) => {
                    l.send(&ToWorker::HostData(data.to_vec()));
                    None
                }
                Inner::Forward { .. } | Inner::Ended => None,
            }
        };
        if let Some((data, rest, client_version)) = reconnect {
            self.resolve_reconnect(data, rest, client_version);
        }
    }

    /// The host's connection is gone. `epoch` is what `host_epoch` was
    /// when that connection became this session's host.
    pub fn host_gone(&self, epoch: u64) {
        if let Some((t, e)) = self.forward_target() {
            return t.host_gone(e);
        }
        if epoch != self.host_epoch.load(Ordering::SeqCst) {
            return;
        }
        let mut inner = self.lock();
        match &mut *inner {
            Inner::Local { driver, .. } => {
                driver.host_gone();
                self.remove_files(driver.tokens());
                self.release_guard();
            }
            Inner::Remote(l) => {
                l.send(&ToWorker::HostGone);
                // The worker answers with the viewers' notices and exits;
                // `read_worker` finishes the cleanup.
            }
            Inner::Forward { .. } | Inner::Ended => {}
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.host_epoch.load(Ordering::SeqCst)
    }

    fn release_guard(&self) {
        self.guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Attaches a viewer that completed its pty and shell requests.
    pub fn attach_viewer(
        &self,
        peer: Peer,
        access: Access,
        ip: &str,
        pubkey: Option<&str>,
        size: Size,
    ) -> ViewerId {
        if let Some((t, _)) = self.forward_target() {
            return t.attach_viewer(peer, access, ip, pubkey, size);
        }
        let id = ViewerId::from_raw(self.next_viewer.fetch_add(1, Ordering::SeqCst));
        match &mut *self.lock() {
            Inner::Local { driver, .. } => {
                driver.attach_viewer(id, peer, access, ip, pubkey, size);
            }
            Inner::Remote(l) => {
                l.viewers.insert(id, peer);
                l.send(&ToWorker::ViewerAttach {
                    id,
                    ip: ip.to_string(),
                    pubkey: pubkey.map(str::to_string),
                    access,
                    size,
                });
            }
            Inner::Forward { .. } | Inner::Ended => {
                peer.send(Payload::Data(Bytes::from_static(hub::SESSION_ENDED)));
                peer.send(Payload::Close);
            }
        }
        id
    }

    pub fn detach_viewer(&self, id: ViewerId) {
        if let Some((t, _)) = self.forward_target() {
            return t.detach_viewer(id);
        }
        match &mut *self.lock() {
            Inner::Local { driver, .. } => driver.detach_viewer(id),
            Inner::Remote(l) => {
                l.viewers.remove(&id);
                l.send(&ToWorker::ViewerDetach(id));
            }
            Inner::Forward { .. } | Inner::Ended => {}
        }
    }

    pub fn resize_viewer(&self, id: ViewerId, size: Size) {
        if let Some((t, _)) = self.forward_target() {
            return t.resize_viewer(id, size);
        }
        match &mut *self.lock() {
            Inner::Local { driver, .. } => driver.resize_viewer(id, size),
            Inner::Remote(l) => l.send(&ToWorker::ViewerResize { id, size }),
            Inner::Forward { .. } | Inner::Ended => {}
        }
    }

    /// Returns the generation to pass to `flush_viewer` when the driver
    /// holds a lone ESC (in-process only; a worker runs its own timer).
    pub fn viewer_input(&self, id: ViewerId, data: &[u8]) -> Option<u64> {
        if let Some((t, _)) = self.forward_target() {
            return t.viewer_input(id, data);
        }
        match &mut *self.lock() {
            Inner::Local { driver, .. } => driver.viewer_input(id, data),
            Inner::Remote(l) => {
                l.send(&ToWorker::ViewerInput {
                    id,
                    data: data.to_vec(),
                });
                None
            }
            Inner::Forward { .. } | Inner::Ended => None,
        }
    }

    pub fn flush_viewer(&self, id: ViewerId, generation: u64) {
        if let Some((t, _)) = self.forward_target() {
            return t.flush_viewer(id, generation);
        }
        if let Inner::Local { driver, .. } = &mut *self.lock() {
            driver.flush_viewer(id, generation);
        }
    }

    /// Verifies RECONNECT data and continues the session accordingly.
    fn resolve_reconnect(self: &Arc<Self>, data: String, rest: Vec<u8>, client_version: String) {
        let tokens = reconnect::verify(&data);
        let live = tokens
            .as_ref()
            .and_then(|t| self.registry.lookup(&t.rw))
            .map(|(h, _)| h)
            .filter(|h| !Arc::ptr_eq(h, self));
        if let (Some(live), Some(_)) = (live, &tokens) {
            // Hand our host connection to the live session.
            let taken = {
                let mut inner = self.lock();
                match &mut *inner {
                    Inner::Local { driver, .. } => driver
                        .hub()
                        .host_peer()
                        .map(|peer| (peer, driver.peer_ip().to_string())),
                    Inner::Remote(l) => l.hosts.remove(&0).map(|peer| (peer, l.peer_ip.clone())),
                    Inner::Forward { .. } | Inner::Ended => None,
                }
            };
            if let Some((peer, peer_ip)) = taken
                && let Some(epoch) = live.adopt_host(peer, peer_ip, client_version, rest.clone())
            {
                let old = std::mem::replace(
                    &mut *self.lock(),
                    Inner::Forward {
                        target: live,
                        epoch,
                    },
                );
                drop(old);
                self.release_guard();
                return;
            }
            warn!("live session vanished during reconnect; starting afresh");
        }
        match &mut *self.lock() {
            Inner::Local { driver, .. } => match tokens {
                Some(t) => driver.reconnect_fresh(t, rest),
                None => driver.reconnect_rejected(rest),
            },
            Inner::Remote(l) => {
                if let Some(t) = &tokens {
                    l.tokens = t.clone();
                }
                let reconnection_data =
                    tokens.as_ref().map(reconnect::data_for).unwrap_or_default();
                l.send(&ToWorker::ReconnectResult {
                    tokens,
                    reconnection_data,
                });
            }
            Inner::Forward { .. } | Inner::Ended => {}
        }
    }

    /// A reconnecting host from `peer_ip` takes this session over. Returns
    /// the host epoch its connection now has, or `None` if the session is
    /// no longer alive.
    fn adopt_host(
        &self,
        host: Peer,
        peer_ip: String,
        client_version: String,
        rest: Vec<u8>,
    ) -> Option<u64> {
        if let Some((t, _)) = self.forward_target() {
            return t.adopt_host(host, peer_ip, client_version, rest);
        }
        let mut inner = self.lock();
        let epoch = self.host_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        match &mut *inner {
            Inner::Local { driver, .. } => {
                if driver.hub().is_ended() {
                    return None;
                }
                driver.adopt_host(host, peer_ip, client_version, rest);
            }
            Inner::Remote(l) => {
                l.hosts.insert(epoch, host);
                l.send(&ToWorker::HostAdopted {
                    epoch,
                    peer_ip,
                    client_version,
                });
                l.send(&ToWorker::HostData(rest));
            }
            Inner::Forward { .. } | Inner::Ended => return None,
        }
        Some(epoch)
    }

    /// A message from this session's worker.
    fn on_worker_msg(self: &Arc<Self>, msg: ToGateway, peer_ip: &str) {
        let reconnect = {
            let mut inner = self.lock();
            let Inner::Remote(link) = &mut *inner else {
                return;
            };
            match msg {
                ToGateway::Ready { sandbox, level } => {
                    if level >= 2 {
                        info!(peer = %peer_ip, pid = link.pid, %sandbox, "session worker sandboxed");
                    } else {
                        warn!(peer = %peer_ip, pid = link.pid, %sandbox, "session worker only partly sandboxed");
                    }
                    None
                }
                ToGateway::ToHost { epoch, data } => {
                    if let Some(h) = link.hosts.get(&epoch) {
                        h.send(Payload::Data(Bytes::from(data)));
                    }
                    None
                }
                ToGateway::CloseHost { epoch } => {
                    if let Some(h) = link.hosts.remove(&epoch) {
                        h.send(Payload::Close);
                    }
                    None
                }
                ToGateway::ToViewer { id, data } => {
                    if let Some(v) = link.viewers.get(&id) {
                        v.send(Payload::Data(Bytes::from(data)));
                    }
                    None
                }
                ToGateway::CloseViewer(id) => {
                    if let Some(v) = link.viewers.remove(&id) {
                        v.send(Payload::Close);
                    }
                    None
                }
                ToGateway::Register(tokens) => {
                    link.tokens = tokens.clone();
                    if !self.registry.insert(&tokens, self.clone()) {
                        tracing::warn!(token = %&tokens.rw[..tokens.rw.len().min(4)], "worker asked for a token held by another session; not registered");
                    }
                    None
                }
                ToGateway::Unregister(tokens) => {
                    self.registry.remove_if(&tokens, self);
                    self.remove_files(&tokens);
                    self.release_guard();
                    None
                }
                ToGateway::AuthorizedKeys { enabled, keys } => {
                    link.auth = enabled.then(|| {
                        keys.iter()
                            .filter_map(|k| match PublicKey::from_openssh(k) {
                                Ok(key) => Some(key),
                                Err(e) => {
                                    debug!(error = %e, "worker sent an unparsable key");
                                    None
                                }
                            })
                            .collect()
                    });
                    None
                }
                ToGateway::Reconnect {
                    data,
                    rest,
                    client_version,
                } => Some((data, rest, client_version)),
                ToGateway::ToBackend(data) => {
                    self.backend_send(data);
                    None
                }
                ToGateway::CloseBackend => {
                    self.backend_close();
                    None
                }
            }
        };
        if let Some((data, rest, client_version)) = reconnect {
            self.resolve_reconnect(data, rest, client_version);
        }
    }

    /// The worker's socket closed: whatever it had not finished is
    /// finished here, so viewers never hang on a dead session.
    fn worker_gone(&self) {
        let mut inner = self.lock();
        if let Inner::Remote(link) = &mut *inner {
            for (_, h) in link.hosts.drain() {
                h.send(Payload::Close);
            }
            for (_, v) in link.viewers.drain() {
                v.send(Payload::Data(Bytes::from_static(hub::SESSION_ENDED)));
                v.send(Payload::Close);
            }
            if let Some(me) = self.me.upgrade() {
                self.registry.remove_if(&link.tokens, &me);
            }
            self.remove_files(&link.tokens);
            *inner = Inner::Ended;
        }
        drop(inner);
        self.backend_close();
        self.release_guard();
    }
}

/// Splits the backend connection into a writer fed by the session and a
/// reader that hands the backend's bytes to it.
fn start_backend(
    handle: Weak<SessionHandle>,
    stream: tokio::net::TcpStream,
    peer_ip: String,
) -> BackendLink {
    let (rd, wr) = stream.into_split();
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(write_backend(wr, rx));
    let reader = tokio::spawn(read_backend(handle, rd, peer_ip));
    BackendLink { tx, reader }
}

async fn write_backend(
    mut wr: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(data) = rx.recv().await {
        if wr.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

async fn read_backend(
    handle: Weak<SessionHandle>,
    mut rd: tokio::net::tcp::OwnedReadHalf,
    peer_ip: String,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => {
                debug!(peer = %peer_ip, "backend closed the session connection");
                break;
            }
            Ok(n) => {
                let Some(h) = handle.upgrade() else {
                    return;
                };
                h.backend_data(&buf[..n]);
            }
            Err(e) => {
                warn!(peer = %peer_ip, error = %e, "backend connection failed");
                break;
            }
        }
    }
    if let Some(h) = handle.upgrade() {
        h.backend_gone();
    }
}

/// Starts `exe --worker` with the worker's end of a socketpair as fd 3.
pub fn spawn_worker(
    exe: &std::path::Path,
    sandbox: SandboxMode,
    verbose: u8,
) -> std::io::Result<(tokio::net::UnixStream, tokio::process::Child)> {
    use std::os::fd::AsRawFd;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("--worker").arg("--sandbox").arg(sandbox.as_str());
    for _ in 0..verbose {
        cmd.arg("-v");
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let fd = theirs.as_raw_fd();
    // SAFETY: dup2 is async-signal-safe and `fd` stays open in the parent
    // until after spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(theirs);
    ours.set_nonblocking(true)?;
    Ok((tokio::net::UnixStream::from_std(ours)?, child))
}

async fn write_frames(
    mut wr: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(frame) = rx.recv().await {
        if wr.write_all(&frame).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

async fn read_worker(
    handle: Weak<SessionHandle>,
    mut rd: tokio::net::unix::OwnedReadHalf,
    mut child: tokio::process::Child,
    peer_ip: String,
) {
    let mut framer = Framer::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut misbehaved = false;
    'read: loop {
        let n = match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        framer.feed(&buf[..n]);
        loop {
            match framer.next_frame() {
                Ok(Some(payload)) => match ToGateway::decode(&payload) {
                    Ok(msg) => {
                        let Some(h) = handle.upgrade() else {
                            break 'read;
                        };
                        h.on_worker_msg(msg, &peer_ip);
                    }
                    Err(e) => {
                        warn!(peer = %peer_ip, error = %e, "bad message from session worker; killing it");
                        misbehaved = true;
                        break 'read;
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    warn!(peer = %peer_ip, error = %e, "bad frame from session worker; killing it");
                    misbehaved = true;
                    break 'read;
                }
            }
        }
    }
    if misbehaved {
        let _ = child.start_kill();
    }
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let description = match status {
        Ok(s) => describe_exit(s),
        Err(_) => {
            let _ = child.start_kill();
            "did not exit after its socket closed; killed".into()
        }
    };
    if description == "exited normally" {
        debug!(peer = %peer_ip, "session worker {description}");
    } else {
        warn!(peer = %peer_ip, "session worker {description}");
    }
    if let Some(h) = handle.upgrade() {
        h.worker_gone();
    }
}

/// Runs a worker just to see how far it gets locking itself down.
pub async fn probe_sandbox(
    exe: &std::path::Path,
    sandbox: SandboxMode,
    verbose: u8,
) -> Result<(u8, String), String> {
    let (stream, mut child) =
        spawn_worker(exe, sandbox, verbose).map_err(|e| format!("cannot start a worker: {e}"))?;
    let (mut rd, wr) = stream.into_split();
    let mut framer = Framer::new();
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = rd.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                return Err(match status {
                    Ok(status) => format!("the worker {} before reporting", describe_exit(status)),
                    Err(_) => "the worker closed its socket before reporting".to_string(),
                });
            }
            framer.feed(&buf[..n]);
            if let Some(payload) = framer.next_frame().map_err(|e| e.to_string())? {
                return match ToGateway::decode(&payload) {
                    Ok(ToGateway::Ready { sandbox, level }) => Ok((level, sandbox)),
                    Ok(other) => Err(format!("unexpected first message {other:?}")),
                    Err(e) => Err(e.to_string()),
                };
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("the worker did not report within 10 s".to_string()));
    drop(wr);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_files_follow_the_backends_renames() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = Tokens::generate();
        let files = SessionFiles::create(dir.path(), &tokens).unwrap();
        let rw = dir.path().join(&tokens.rw);
        let ro = dir.path().join(&tokens.ro);
        assert!(rw.is_file());
        assert_eq!(
            std::fs::read_link(&ro).unwrap(),
            PathBuf::from(&tokens.rw),
            "the read-only entry is a symlink to the socket, as the backend expects"
        );
        assert!(
            SessionFiles::create(dir.path(), &tokens).is_err(),
            "a token in use is never reused"
        );
        // What `rename_tmux_sockets!` does for a named session.
        let named = Tokens {
            rw: "acme/demo".into(),
            ro: "ro-acme/demo-2".into(),
        };
        std::fs::rename(&rw, dir.path().join("acme=demo")).unwrap();
        std::fs::remove_file(&ro).unwrap();
        std::os::unix::fs::symlink("acme=demo", dir.path().join("ro-acme=demo-2")).unwrap();
        files.remove(&named);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        // Names that are not tokens are never touched.
        std::fs::write(dir.path().join("x"), b"").unwrap();
        files.remove(&Tokens {
            rw: "../x".into(),
            ro: "x".into(),
        });
        assert!(dir.path().join("x").exists());
    }
}
