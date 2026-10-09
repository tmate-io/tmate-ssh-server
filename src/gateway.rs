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

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::server::{Auth, Config, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Disconnect};
use tracing::{debug, info, warn};

use crate::cut::Cut;
use crate::hub::{self, Payload, Peer, ViewerId};
use crate::limits::{RateLimiter, SessionCounter};
use crate::link::{Env, SessionHandle};
use crate::msgpack::Encoder;
use crate::proto;
use crate::render::Size;
use crate::session::{self, Access};

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
    access: Access,
    size: Size,
    /// Set once the shell request attached us to the session.
    id: Option<ViewerId>,
}

enum Role {
    Unassigned,
    /// Authenticated as `tmate`, waiting for the subsystem request.
    HostCandidate,
    Host(HostState),
    Viewer(ViewerState),
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
            Role::Unassigned | Role::HostCandidate => {}
        }
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
        if name != "tmate" || !matches!(self.role, Role::HostCandidate) {
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        self.role_chosen.send_replace(true);
        let peer = Peer::spawn(session.handle(), channel, self.cut.clone());
        match self.sessions.acquire(self.peer_ip) {
            Ok(guard) => {
                let handle = SessionHandle::start(&self.env, self.peer.clone(), peer, guard);
                self.role = Role::Host(HostState {
                    epoch: handle.current_epoch(),
                    session: handle,
                    rate: RateLimiter::new(self.host_rate_limit, RATE_PATIENCE, Instant::now()),
                });
            }
            Err(refusal) => {
                // The client prints notices as they come, so it learns why
                // before the channel closes.
                warn!(peer = %self.peer, %refusal, "session refused");
                let mut enc = Encoder::new();
                proto::encode_notify(&mut enc, &format!("Session refused: {refusal}."));
                proto::encode_notify(&mut enc, "Press <Ctrl-c><Ctrl-d> to exit.");
                peer.send(Payload::Data(enc.take().into()));
                peer.send(Payload::Close);
            }
        }
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
        let Role::Viewer(v) = &mut self.role else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        v.size = terminal_size(col_width, row_height);
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
        let id = v.session.attach_viewer(peer, v.access, &self.peer, v.size);
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
        // otherwise. Unknown tokens are already rejected at auth here, so
        // the only thing left to say is that there is nothing to run.
        const UNSUPPORTED: &[u8] = b"tmate: command execution is not supported on this server\r\n";
        let taken = match &self.role {
            Role::HostCandidate => false,
            Role::Viewer(v) => v.id.is_some(),
            Role::Unassigned | Role::Host(_) => true,
        };
        if Some(channel) != self.channel || taken {
            session.channel_failure(channel)?;
            return Ok(());
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
            Role::Unassigned | Role::HostCandidate => {}
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
        if user == "tmate" {
            self.role = Role::HostCandidate;
            return Ok(Auth::Accept);
        }
        if !session::is_valid_token(user) {
            return Ok(Auth::reject());
        }
        let Some((handle, access)) = self.env.registry.lookup(user) else {
            return Ok(Auth::reject());
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
            access,
            size: Size { cols: 80, rows: 24 },
            id: None,
        });
        Ok(Auth::Accept)
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
