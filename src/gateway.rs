//! SSH front door. One `Connection` per TCP client; a connection becomes a
//! host (subsystem `tmate`) or a viewer (shell request with a token as the
//! username) after authentication.
//!
//! The gateway never interprets what a host sends: the bytes go to the
//! session's `SessionHandle` (`link.rs`), which decodes them in this
//! process or in a sandboxed worker, and whatever must go back to a
//! connection arrives through its `hub::Peer` writer, so the order the
//! session produced is kept. What the gateway does keep for itself is
//! authentication, the resource limits and the SSH plumbing.
//!
//! With a backend (`-w`), exec requests (`ssh token@host command`) are
//! served the way `tmate-ssh-exec.c` did: a connection of their own to
//! the backend, `CTL_EXEC`, and the `CTL_EXEC_RESPONSE` written back to
//! the client with its exit status. A viewer with a token nobody holds is
//! turned into an `explain-session-not-found` exec, so the backend can say
//! what became of the session.

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::server::{Auth, Config, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Disconnect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::backend::{self, CtlIn};
use crate::cut::Cut;
use crate::hub::{self, Payload, Peer, ViewerId};
use crate::limits::{RateLimiter, SessionCounter};
use crate::link::{self, Env, SessionHandle};
use crate::msgpack::{Decoder, Encoder};
use crate::proto;
use crate::render::Size;
use crate::session::{self, Access};

/// How long an exec request may wait for the backend's answer.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// What an exec client gets when the backend cannot be reached or does
/// not answer (`on_websocket_error` in `tmate-ssh-exec.c`).
pub const EXEC_INTERNAL_ERROR: &str = "Internal Error\r\n";

/// The exec command a viewer of an unknown session is turned into.
pub const EXPLAIN_SESSION_NOT_FOUND: &str = "explain-session-not-found";

/// How long a host may stay over its byte rate before it is dropped.
pub const RATE_PATIENCE: Duration = Duration::from_secs(5);

/// How long a client told to disconnect may keep its connection open
/// before it is cut.
pub const DISCONNECT_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Gateway {
    pub env: Arc<Env>,
    pub sessions: Arc<SessionCounter>,
    /// Bytes per second a host may send (sustained).
    pub host_rate_limit: usize,
}

impl Server for Gateway {
    type Handler = Connection;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> Connection {
        Connection {
            env: self.env.clone(),
            sessions: self.sessions.clone(),
            host_rate_limit: self.host_rate_limit,
            peer_ip: peer.map(|p| p.ip()),
            peer: peer
                .map(|p| p.ip().to_string())
                .unwrap_or_else(|| "?".into()),
            channel: None,
            role: Role::Unassigned,
            role_chosen: tokio::sync::watch::channel(false).0,
            cut: Cut::new(),
        }
    }

    fn handle_session_error(&mut self, error: russh::Error) {
        debug!(%error, "connection ended with error");
    }
}

struct HostState {
    session: Arc<SessionHandle>,
    /// The session's host epoch for this connection (see `SessionHandle`).
    epoch: u64,
    rate: RateLimiter,
}

struct ViewerState {
    session: Arc<SessionHandle>,
    user: String,
    pubkey: Option<String>,
    access: Access,
    size: Size,
    /// Set once the shell request attached us to the session.
    id: Option<ViewerId>,
}

enum Role {
    Unassigned,
    /// Authenticated as `tmate`, waiting for the subsystem request.
    HostCandidate {
        pubkey: Option<String>,
    },
    Host(HostState),
    Viewer(ViewerState),
    /// A token no session holds, let in because a backend can explain
    /// (`tmate_spawn_pty_client` with a backend); whatever it asks for
    /// becomes an exec.
    Stranger {
        user: String,
        pubkey: Option<String>,
    },
    /// Running an exec request; nothing else is served.
    Exec,
}

pub struct Connection {
    env: Arc<Env>,
    sessions: Arc<SessionCounter>,
    host_rate_limit: usize,
    peer_ip: Option<std::net::IpAddr>,
    peer: String,
    channel: Option<ChannelId>,
    role: Role,
    /// Flips to true once the connection is a host, a viewer or an exec
    /// request; `accept.rs` closes connections that take too long to get
    /// there (the old `TMATE_SSH_GRACE_PERIOD`). Subscribe to watch it.
    pub(crate) role_chosen: tokio::sync::watch::Sender<bool>,
    /// Ends this connection's TCP stream; `accept.rs` wires it to the
    /// stream before russh gets it. Peers use it to cut a client that
    /// stops draining, since russh cannot be told to from outside.
    pub(crate) cut: Cut,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.leave();
    }
}

impl Connection {
    /// Removes this connection from its session. Safe to call more than
    /// once: the channel close, EOF and drop paths all end up here.
    fn leave(&mut self) {
        match &mut self.role {
            Role::Host(h) => {
                h.session.host_gone(h.epoch);
                self.role = Role::Unassigned;
            }
            Role::Viewer(v) => {
                if let Some(id) = v.id.take() {
                    v.session.detach_viewer(id);
                    info!(peer = %self.peer, "viewer left");
                }
            }
            Role::Unassigned | Role::HostCandidate { .. } | Role::Stranger { .. } | Role::Exec => {}
        }
    }

    /// Serves `command` through the backend on a task of its own and
    /// closes the channel with the answer (`tmate_spawn_exec`).
    fn start_exec(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        addr: backend::Addr,
        user: String,
        pubkey: Option<String>,
        command: String,
    ) -> Result<(), russh::Error> {
        info!(peer = %self.peer, %user, %command, "exec request");
        self.role = Role::Exec;
        self.role_chosen.send_replace(true);
        session.channel_success(channel)?;
        tokio::spawn(run_exec(
            addr,
            session.handle(),
            channel,
            user,
            self.peer.clone(),
            pubkey,
            command,
            self.cut.clone(),
        ));
        Ok(())
    }

    /// Ends the connection with `why` as the DISCONNECT reason. Returning
    /// normally lets russh flush the message (an `Err` drops the stream
    /// before it is written); the cut then bounds how long a client that
    /// never closes its side can keep the connection.
    fn fail(&mut self, session: &mut Session, why: &str) -> Result<(), russh::Error> {
        warn!(peer = %self.peer, "{why}");
        self.leave();
        session.disconnect(Disconnect::ProtocolError, why, "")?;
        self.cut.cut_after(DISCONNECT_GRACE);
        Ok(())
    }

    fn on_viewer_input(&mut self, data: &[u8]) {
        let Role::Viewer(v) = &self.role else {
            return;
        };
        let Some(id) = v.id else {
            return;
        };
        if let Some(generation) = v.session.viewer_input(id, data) {
            // A lone ESC might be the start of a sequence split across
            // packets; after the delay it is sent as a plain Escape.
            let session = v.session.clone();
            tokio::spawn(async move {
                tokio::time::sleep(hub::ESC_FLUSH_DELAY).await;
                session.flush_viewer(id, generation);
            });
        }
    }
}

/// A zero dimension means the client has no idea (ssh without a local
/// tty); tmux falls back to 80x24 in that case and so do we.
fn terminal_size(cols: u32, rows: u32) -> Size {
    let dim = |n: u32, fallback: u16| {
        if n == 0 {
            fallback
        } else {
            u16::try_from(n).unwrap_or(u16::MAX)
        }
    };
    Size {
        cols: dim(cols, 80),
        rows: dim(rows, 24),
    }
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.authenticate(user, None)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.authenticate(user, Some(key))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channel.is_some() {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.channel = Some(channel.id());
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Role::HostCandidate { pubkey } = &self.role else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if name != "tmate" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let pubkey = pubkey.clone();
        session.channel_success(channel)?;
        self.role_chosen.send_replace(true);
        let peer = Peer::spawn(session.handle(), channel, self.cut.clone());
        let guard = match self.sessions.acquire(self.peer_ip) {
            Ok(guard) => guard,
            Err(refusal) => {
                // The client prints notices as they come, so it learns why
                // before the channel closes.
                warn!(peer = %self.peer, %refusal, "session refused");
                refuse_session(&peer, &format!("Session refused: {refusal}."));
                return Ok(());
            }
        };
        // "We should die early if we can't connect to websocket server":
        // without its backend connection the session is not started.
        let backend = match &self.env.backend {
            None => None,
            Some(addr) => match link::connect_backend(addr).await {
                Ok(stream) => Some(stream),
                Err(e) => {
                    warn!(peer = %self.peer, backend = %addr, error = %e, "cannot connect to the backend; refusing the session");
                    refuse_session(
                        &peer,
                        "Session refused: the server's backend is unavailable.",
                    );
                    return Ok(());
                }
            },
        };
        let handle =
            SessionHandle::start(&self.env, self.peer.clone(), pubkey, peer, guard, backend);
        self.role = Role::Host(HostState {
            epoch: handle.current_epoch(),
            session: handle,
            rate: RateLimiter::new(self.host_rate_limit, RATE_PATIENCE, Instant::now()),
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match &mut self.role {
            Role::Viewer(v) => v.size = terminal_size(col_width, row_height),
            // The explanation it is about to get needs no terminal, but
            // `ssh` without `-T` asks for one.
            Role::Stranger { .. } => {}
            _ => {
                session.channel_failure(channel)?;
                return Ok(());
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Role::Viewer(v) = &mut self.role else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        v.size = terminal_size(col_width, row_height);
        if let Some(id) = v.id {
            v.session.resize_viewer(id, v.size);
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let (Role::Stranger { user, pubkey }, Some(addr)) = (&self.role, &self.env.backend) {
            let (user, pubkey, addr) = (user.clone(), pubkey.clone(), addr.clone());
            return self.start_exec(
                session,
                channel,
                addr,
                user,
                pubkey,
                EXPLAIN_SESSION_NOT_FOUND.into(),
            );
        }
        let Role::Viewer(v) = &mut self.role else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if v.id.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        // The reply is written directly and so precedes the first frame,
        // which goes through the writer task.
        session.channel_success(channel)?;
        self.role_chosen.send_replace(true);
        let peer = Peer::spawn(session.handle(), channel, self.cut.clone());
        let id = v
            .session
            .attach_viewer(peer, v.access, &self.peer, v.pubkey.as_deref(), v.size);
        v.id = Some(id);
        let token = v
            .session
            .tokens()
            .map(|t| t.rw[..4].to_string())
            .unwrap_or_default();
        info!(peer = %self.peer, %token, access = ?v.access, "viewer attached");
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `ssh token@host some-command`. The old server only served exec
        // requests through its websocket backend (`tmate-ssh-exec.c`, used
        // for `explain-session-not-found` and friends) and refused them
        // otherwise; the same here.
        const UNSUPPORTED: &[u8] = b"tmate: command execution is not supported on this server\r\n";
        let who = match &self.role {
            Role::HostCandidate { pubkey } => Some(("tmate".to_string(), pubkey.clone())),
            Role::Viewer(v) if v.id.is_none() => Some((v.user.clone(), v.pubkey.clone())),
            Role::Stranger { user, pubkey } => Some((user.clone(), pubkey.clone())),
            Role::Viewer(_) | Role::Unassigned | Role::Host(_) | Role::Exec => None,
        };
        let Some((user, pubkey)) = who.filter(|_| Some(channel) == self.channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Some(addr) = self.env.backend.clone() {
            let command = String::from_utf8_lossy(command).into_owned();
            return self.start_exec(session, channel, addr, user, pubkey, command);
        }
        info!(peer = %self.peer, command = %String::from_utf8_lossy(command), "exec request refused");
        self.role_chosen.send_replace(true);
        session.channel_success(channel)?;
        session.data(channel, bytes::Bytes::from_static(UNSUPPORTED))?;
        session.exit_status_request(channel, 1)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if Some(channel) != self.channel {
            return Ok(());
        }
        match &mut self.role {
            Role::Viewer(_) => self.on_viewer_input(data),
            Role::Host(host) => {
                if !host.rate.allow(data.len(), Instant::now()) {
                    let why = format!(
                        "host sent more than {} bytes/s for {} s; dropping the session",
                        self.host_rate_limit,
                        RATE_PATIENCE.as_secs()
                    );
                    return self.fail(session, &why);
                }
                host.session.host_data(data);
            }
            Role::Unassigned | Role::HostCandidate { .. } | Role::Stranger { .. } | Role::Exec => {}
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if Some(channel) == self.channel {
            self.leave();
            session.close(channel)?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if Some(channel) == self.channel {
            self.leave();
        }
        Ok(())
    }
}

impl Connection {
    fn authenticate(
        &mut self,
        user: &str,
        key: Option<&russh::keys::PublicKey>,
    ) -> Result<Auth, russh::Error> {
        let pubkey = key.and_then(|k| k.to_openssh().ok());
        if user == "tmate" {
            self.role = Role::HostCandidate { pubkey };
            return Ok(Auth::Accept);
        }
        let acceptable = match self.env.backend {
            // A backend names sessions, so tokens may look like names.
            Some(_) => session::is_acceptable_token(user),
            None => session::is_valid_token(user),
        };
        if !acceptable {
            return Ok(Auth::reject());
        }
        let Some((handle, access)) = self.env.registry.lookup(user) else {
            if self.env.backend.is_none() {
                return Ok(Auth::reject());
            }
            // The old server let the client in and only then found no
            // session to attach to; the backend explains why.
            debug!(peer = %self.peer, "unknown token; the backend will explain");
            self.role = Role::Stranger {
                user: user.to_string(),
                pubkey,
            };
            return Ok(Auth::Accept);
        };
        if handle.keys_enabled() {
            // Rejecting "none" with publickey as the way forward makes the
            // client offer its keys instead of giving up.
            if key.is_none() {
                let mut methods = russh::MethodSet::empty();
                methods.push(russh::MethodKind::PublicKey);
                return Ok(Auth::Reject {
                    proceed_with_methods: Some(methods),
                    partial_success: false,
                });
            }
            if !handle.authorize(key) {
                debug!(peer = %self.peer, "viewer key not in the session's authorized keys");
                return Ok(Auth::reject());
            }
        }
        debug!(peer = %self.peer, has_key = key.is_some(), "viewer authenticated");
        self.role = Role::Viewer(ViewerState {
            session: handle,
            user: user.to_string(),
            pubkey,
            access,
            size: Size { cols: 80, rows: 24 },
            id: None,
        });
        Ok(Auth::Accept)
    }
}

/// Tells a host why it gets no session and closes its channel.
fn refuse_session(peer: &Peer, why: &str) {
    let mut enc = Encoder::new();
    proto::encode_notify(&mut enc, why);
    proto::encode_notify(&mut enc, "Press <Ctrl-c><Ctrl-d> to exit.");
    peer.send(Payload::Data(enc.take().into()));
    peer.send(Payload::Close);
}

/// Asks the backend to run `command` for an exec client and relays the
/// answer: `CTL_EXEC` on a fresh connection, then the message and exit
/// status of the `CTL_EXEC_RESPONSE`.
#[allow(clippy::too_many_arguments)]
async fn run_exec(
    addr: backend::Addr,
    handle: russh::server::Handle,
    channel: ChannelId,
    user: String,
    ip: String,
    pubkey: Option<String>,
    command: String,
    cut: Cut,
) {
    let (exit_code, message) = match tokio::time::timeout(
        EXEC_TIMEOUT,
        exec_on_backend(&addr, &user, &ip, pubkey.as_deref(), &command),
    )
    .await
    {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => {
            warn!(peer = %ip, backend = %addr, error = %e, "exec request failed");
            (1, EXEC_INTERNAL_ERROR.to_string())
        }
        Err(_) => {
            warn!(peer = %ip, backend = %addr, "exec request timed out");
            (1, EXEC_INTERNAL_ERROR.to_string())
        }
    };
    let status = u32::try_from(exit_code).unwrap_or(1);
    let _ = handle.data(channel, bytes::Bytes::from(message)).await;
    let _ = handle.exit_status_request(channel, status).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
    cut.cut_after(hub::CLOSE_GRACE);
}

async fn exec_on_backend(
    addr: &backend::Addr,
    user: &str,
    ip: &str,
    pubkey: Option<&str>,
    command: &str,
) -> std::io::Result<(i64, String)> {
    let mut stream = link::connect_backend(addr).await?;
    let mut enc = Encoder::new();
    backend::encode_exec(&mut enc, user, ip, pubkey, command);
    stream.write_all(&enc.take()).await?;
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "backend closed before answering",
            ));
        }
        dec.feed(&buf[..n]);
        while let Some(value) = dec.next_value().map_err(std::io::Error::other)? {
            match CtlIn::parse(&value) {
                Ok(CtlIn::ExecResponse { exit_code, message }) => return Ok((exit_code, message)),
                Ok(other) => debug!(?other, "ignoring backend message on an exec connection"),
                Err(e) => debug!(error = %e, "ignoring backend message on an exec connection"),
            }
        }
    }
}

pub fn ssh_config(keys: Vec<russh::keys::PrivateKey>) -> Config {
    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::None);
    methods.push(russh::MethodKind::PublicKey);
    Config {
        server_id: russh::SshId::Standard("SSH-2.0-tmate".into()),
        methods,
        keys,
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keepalive_interval: Some(std::time::Duration::from_secs(300)),
        keepalive_max: 3,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    }
}
