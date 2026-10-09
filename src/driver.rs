//! Everything a session does with what its host sends: decoding the
//! msgpack stream, the handshake (HEADER, READY, FIN, RECONNECT) and feeding
//! the `Hub` with the rest. This is the code that touches untrusted bytes,
//! so it is written to run either in the gateway process (in-process mode)
//! or inside a sandboxed worker, with the few things that need the gateway
//! (the token registry, viewer authentication, reconnection data signed by
//! the gateway, the TCP connection to the backend) behind the `Control`
//! trait.
//!
//! With a backend (`-w`), the driver also speaks the control protocol
//! (`backend.rs`) on the session's behalf, as `tmate-websocket.c` did:
//! `CTL_HEADER` at the host's HEADER, every host message forwarded as
//! `CTL_DEAMON_OUT_MSG`, viewers announced with `CTL_CLIENT_JOIN`/`LEFT`,
//! and the backend's messages applied: forwarded messages go to the host
//! (the notices, `SET_ENV` and READY the driver would otherwise produce
//! itself), keys to the host's panes, the web clients' size into the size
//! rule, snapshots answered from the hub, and renamed sessions
//! re-registered.

use std::collections::BTreeSet;
use std::sync::Arc;

use russh::keys::PublicKey;
use tracing::{debug, info, warn};

use crate::backend::{self, CtlIn};
use crate::hub::{self, Hub, Peer, ViewerId};
use crate::msgpack::{Decoder, Encoder};
use crate::proto::{self, HostMsg, PROTOCOL_VERSION};
use crate::render::Size;
use crate::session::{Access, Tokens};

/// How the server tells hosts to reach it.
#[derive(Debug, Clone)]
pub struct Advertised {
    pub host: String,
    pub port: u16,
}

impl Advertised {
    pub fn ssh_command(&self, token: &str) -> String {
        if self.port == 22 {
            format!("ssh {token}@{}", self.host)
        } else {
            format!("ssh -p{} {token}@{}", self.port, self.host)
        }
    }
}

/// What the driver needs from the gateway.
pub trait Control: Send {
    /// The session is ready for viewers under `tokens`.
    fn register(&self, tokens: &Tokens);
    fn unregister(&self, tokens: &Tokens);
    /// The host's authorized-keys list changed (`enabled` false: anyone
    /// may join).
    fn authorized_keys(&self, enabled: bool, keys: &[PublicKey]);
    /// Signed reconnection data for `tokens`, to hand to the host.
    fn reconnection_data(&self, tokens: &Tokens) -> String;
    /// The host sent RECONNECT. Decoding pauses until the gateway answers
    /// with `Driver::reconnect_fresh`/`reconnect_rejected`, or hands the
    /// connection to the live session (`Driver::adopt_host` there); `rest`
    /// is what followed the RECONNECT, undecoded.
    fn reconnect(&self, data: String, rest: Vec<u8>, client_version: String);
    /// Bytes for the session's backend connection (backend mode only).
    fn backend_send(&self, data: Vec<u8>);
    /// The session is done with its backend connection.
    fn backend_close(&self);
}

/// What a driver is started with.
#[derive(Debug, Clone)]
pub struct Config {
    pub tokens: Tokens,
    pub keys_required: bool,
    pub peer_ip: String,
    /// The key the host authenticated with, in OpenSSH one-line form.
    pub host_pubkey: Option<String>,
    pub advertised: Arc<Advertised>,
    /// A backend connection exists for this session.
    pub backend: bool,
}

pub struct Driver {
    hub: Arc<Hub>,
    tokens: Tokens,
    decoder: Decoder,
    peer_ip: String,
    host_pubkey: Option<String>,
    advertised: Arc<Advertised>,
    keys_required: bool,
    client_version: Option<String>,
    client_protocol: i64,
    registered: bool,
    /// Waiting for the gateway's verdict on RECONNECT; bytes queue up.
    awaiting_reconnect: bool,
    /// The host connection was closed (by us or by it); nothing more is
    /// decoded. Adoption by a reconnecting host reopens it.
    closed: bool,
    keys_sent: u64,
    backend: bool,
    backend_decoder: Decoder,
    /// Viewers the backend was told about, so it is told when they leave.
    announced: BTreeSet<ViewerId>,
    control: Box<dyn Control>,
}

impl Driver {
    pub fn new(config: Config, host: Peer, control: Box<dyn Control>) -> Driver {
        let hub = Hub::new(config.keys_required, config.backend);
        hub.set_host(host);
        Driver {
            hub,
            tokens: config.tokens,
            decoder: Decoder::new(),
            peer_ip: config.peer_ip,
            host_pubkey: config.host_pubkey,
            advertised: config.advertised,
            keys_required: config.keys_required,
            client_version: None,
            client_protocol: 0,
            registered: false,
            awaiting_reconnect: false,
            closed: false,
            keys_sent: 0,
            backend: config.backend,
            backend_decoder: Decoder::new(),
            announced: BTreeSet::new(),
            control,
        }
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    pub fn tokens(&self) -> &Tokens {
        &self.tokens
    }

    #[cfg(test)]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Bytes from the host.
    pub fn host_data(&mut self, data: &[u8]) {
        if self.closed {
            return;
        }
        self.decoder.feed(data);
        self.pump();
    }

    /// Decodes and handles messages until the input runs dry, the
    /// connection closes, or a RECONNECT needs the gateway. With a backend
    /// every message is also forwarded to it verbatim
    /// (`on_daemon_decoder_read`), after it was handled here; FIN goes
    /// first, since handling it closes the backend connection.
    fn pump(&mut self) {
        while !self.closed && !self.awaiting_reconnect {
            let (value, raw) = match self.decoder.next_value_raw() {
                Ok(Some(v)) => v,
                Ok(None) => break,
                Err(e) => return self.fail(&format!("bad msgpack from host: {e}")),
            };
            let msg = match HostMsg::parse(&value) {
                Ok(m) => m,
                Err(e) => return self.fail(&format!("bad message from host: {e}")),
            };
            let fin = matches!(msg, HostMsg::Fin);
            if fin {
                self.forward_to_backend(&raw);
            }
            self.on_host_msg(msg);
            if !fin && !self.closed {
                self.forward_to_backend(&raw);
            }
            self.sync_keys();
        }
    }

    /// `CTL_DEAMON_OUT_MSG` with the host's bytes as they came.
    fn forward_to_backend(&mut self, raw: &[u8]) {
        if !self.backend {
            return;
        }
        let mut enc = Encoder::new();
        backend::encode_daemon_out_msg(&mut enc, raw);
        self.control.backend_send(enc.take());
    }

    fn ssh_cmd_fmt(&self) -> String {
        self.advertised.ssh_command("%s")
    }

    /// Tells the gateway about a changed key list.
    fn sync_keys(&mut self) {
        let (generation, keys) = self.hub.authorized_keys();
        if generation != self.keys_sent {
            self.keys_sent = generation;
            self.control
                .authorized_keys(keys.is_some(), keys.as_deref().unwrap_or(&[]));
        }
    }

    /// Protocol violation: the host is cut off and the session ends.
    fn fail(&mut self, why: &str) {
        warn!(peer = %self.peer_ip, "{why}");
        self.hub.close_host();
        self.host_gone();
    }

    /// The host connection is gone (or being closed): the session ends.
    pub fn host_gone(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.leave();
    }

    fn leave(&mut self) {
        if self.registered {
            self.control.unregister(&self.tokens);
            self.registered = false;
            info!(peer = %self.peer_ip, "host session closed");
        }
        self.hub.end();
        if self.backend {
            self.control.backend_close();
        }
    }

    fn on_host_msg(&mut self, msg: HostMsg) {
        let mut enc = Encoder::new();
        match msg {
            HostMsg::Header { protocol, version } => {
                if protocol != PROTOCOL_VERSION {
                    proto::encode_notify(
                        &mut enc,
                        &format!(
                            "This server needs tmate 2.4.0 (protocol {PROTOCOL_VERSION}); yours speaks protocol {protocol}"
                        ),
                    );
                    self.hub.send_host(enc.take().into());
                    return self.fail("unsupported protocol version");
                }
                info!(peer = %self.peer_ip, client = %version, "host connected");
                self.client_version = Some(version);
                self.client_protocol = protocol;
                if self.backend {
                    // `tmate_header`: the backend takes over the
                    // notifications from here.
                    backend::encode_header(
                        &mut enc,
                        &backend::Header {
                            ip: &self.peer_ip,
                            pubkey: self.host_pubkey.as_deref(),
                            tokens: &self.tokens,
                            ssh_cmd_fmt: &self.ssh_cmd_fmt(),
                            client_version: self.client_version.as_deref().unwrap_or(""),
                            client_protocol: self.client_protocol,
                        },
                    );
                    self.control.backend_send(enc.take());
                }
            }
            HostMsg::Uname(fields) => debug!(peer = %self.peer_ip, ?fields, "host uname"),
            HostMsg::Ready => {
                if self.client_version.is_none() {
                    return self.fail("READY before HEADER");
                }
                if self.hub.missing_required_keys() {
                    for line in hub::AUTHORIZED_KEYS_ONLY_ERROR_MSG {
                        proto::encode_notify(&mut enc, line);
                    }
                    proto::encode_notify(&mut enc, "");
                    self.hub.send_host(enc.take().into());
                    self.hub.close_host();
                    warn!(peer = %self.peer_ip, "host has no authorized keys; refused");
                    return self.host_gone();
                }
                if self.hub.keys_enabled() {
                    info!(peer = %self.peer_ip, num_keys = self.hub.authorized_key_count(), "restricting ssh access");
                }
                let reconnected = self.hub.take_reconnected();
                if !self.backend {
                    self.send_links(reconnected);
                }
                if !self.registered {
                    // The key list must be known before anyone can join.
                    self.sync_keys();
                    self.control.register(&self.tokens);
                    self.registered = true;
                }
                self.hub.host_ready();
                info!(peer = %self.peer_ip, token = %self.short_token(), reconnected, "session ready");
            }
            HostMsg::ExecCmd(args) => {
                debug!(peer = %self.peer_ip, ?args, "replicated command");
                self.hub.host_msg(&HostMsg::ExecCmd(args));
            }
            HostMsg::ExecCmdStr(cmd) => {
                debug!(peer = %self.peer_ip, %cmd, "replicated command string")
            }
            HostMsg::Fin => {
                info!(peer = %self.peer_ip, "host sent FIN");
                self.hub.close_host();
                self.host_gone();
            }
            HostMsg::Reconnect(data) => {
                if self.registered {
                    return self.fail("RECONNECT after READY");
                }
                if self.backend {
                    // The backend issued the data and verifies it; it
                    // answers with a RENAME_SESSION to the old tokens and
                    // ends whatever session still holds them.
                    return;
                }
                // Only data the gateway signed is honoured; it decides.
                self.awaiting_reconnect = true;
                let rest = self.decoder.take_pending();
                let version = self.client_version.clone().unwrap_or_default();
                self.control.reconnect(data, rest, version);
            }
            msg @ (HostMsg::SyncLayout(_)
            | HostMsg::PtyData { .. }
            | HostMsg::Status { .. }
            | HostMsg::SyncCopyMode { .. }
            | HostMsg::WriteCopyMode { .. }
            | HostMsg::Snapshot(_)
            | HostMsg::FailedCmd { .. }) => {
                self.hub.host_msg(&msg);
            }
        }
    }

    /// The notices, links and READY a host gets without a backend
    /// (`tmate_header` and `tmate_ready` in the old server, the backend's
    /// `finalize_session_init` for the wording).
    fn send_links(&mut self, reconnected: bool) {
        let mut enc = Encoder::new();
        let rw = self.advertised.ssh_command(&self.tokens.rw);
        let ro = self.advertised.ssh_command(&self.tokens.ro);
        // A reconnected host already has its links; it is told so
        // instead, as the Elixir backend did.
        if reconnected {
            proto::encode_notify(&mut enc, hub::RECONNECTED_MSG);
        } else {
            proto::encode_notify(
                &mut enc,
                "Note: clear your terminal before sharing readonly access",
            );
            proto::encode_notify(&mut enc, &format!("ssh session read only: {ro}"));
        }
        proto::encode_set_env(&mut enc, "tmate_ssh_ro", &ro);
        if !reconnected {
            proto::encode_notify(&mut enc, &format!("ssh session: {rw}"));
        }
        proto::encode_set_env(&mut enc, "tmate_ssh", &rw);
        proto::encode_set_env(
            &mut enc,
            "tmate_num_clients",
            &self.hub.num_clients().to_string(),
        );
        proto::encode_set_env(
            &mut enc,
            "tmate_reconnection_data",
            &self.control.reconnection_data(&self.tokens),
        );
        proto::encode_ready(&mut enc);
        self.hub.send_host(enc.take().into());
    }

    /// The token as the log shows it.
    fn short_token(&self) -> String {
        self.tokens.rw.chars().take(4).collect()
    }

    /// Bytes from the backend connection.
    pub fn backend_data(&mut self, data: &[u8]) {
        if self.closed || !self.backend {
            return;
        }
        self.backend_decoder.feed(data);
        while !self.closed {
            let value = match self.backend_decoder.next_value() {
                Ok(Some(v)) => v,
                Ok(None) => break,
                Err(e) => return self.fail(&format!("bad msgpack from the backend: {e}")),
            };
            match CtlIn::parse(&value) {
                Ok(msg) => self.on_backend_msg(msg),
                // `tmate_dispatch_websocket_message`: logged, not fatal.
                Err(e) => warn!(peer = %self.peer_ip, "ignoring backend message: {e}"),
            }
        }
    }

    fn on_backend_msg(&mut self, msg: CtlIn) {
        let mut enc = Encoder::new();
        match msg {
            CtlIn::FwdMsg(value) => {
                enc.value(&value);
                self.hub.send_host(enc.take().into());
            }
            CtlIn::RequestSnapshot { max_history_lines } => {
                let limit = usize::try_from(max_history_lines)
                    .unwrap_or(0)
                    .min(hub::SCROLLBACK);
                let panes = self.hub.snapshot(limit);
                backend::encode_snapshot(&mut enc, &panes);
                self.control.backend_send(enc.take());
            }
            CtlIn::PaneKeys { pane, keys } => {
                // `ctl_pane_keys`: one key per byte, straight to the pane.
                for key in keys {
                    proto::encode_pane_key(&mut enc, pane, u64::from(key));
                }
                self.hub.send_host(enc.take().into());
            }
            CtlIn::Resize { sx, sy } => self.hub.backend_resize(sx, sy),
            CtlIn::ExecResponse { .. } => {
                debug!(peer = %self.peer_ip, "ignoring an exec response on a session connection");
            }
            CtlIn::RenameSession(tokens) => {
                if tokens == self.tokens {
                    return;
                }
                info!(peer = %self.peer_ip, from = %self.short_token(), to = %tokens.rw.chars().take(4).collect::<String>(), "session renamed by the backend");
                if self.registered {
                    self.control.unregister(&self.tokens);
                    self.control.register(&tokens);
                }
                self.tokens = tokens;
            }
        }
    }

    /// The backend connection closed or failed. Without it the session
    /// cannot go on (`on_websocket_event_default`), unless the host
    /// already said FIN.
    pub fn backend_gone(&mut self) {
        if self.closed || !self.backend {
            return;
        }
        warn!(peer = %self.peer_ip, "backend connection lost; ending the session");
        self.hub.close_host();
        self.host_gone();
    }

    /// The gateway could not verify the reconnection data: the session
    /// goes on as a new one, as the old server did for unknown data.
    pub fn reconnect_rejected(&mut self, rest: Vec<u8>) {
        warn!(peer = %self.peer_ip, "ignoring reconnection data not signed by this server");
        self.resume(rest);
    }

    /// Valid reconnection data for a session that is gone: the tokens are
    /// reused for a fresh session, which the snapshot that follows fills.
    pub fn reconnect_fresh(&mut self, tokens: Tokens, rest: Vec<u8>) {
        info!(peer = %self.peer_ip, token = %&tokens.rw[..4], "host reconnected to an ended session; tokens reused");
        let host = self.hub.host_peer();
        self.hub = Hub::new_reconnected(self.keys_required, self.backend);
        self.tokens = tokens;
        if let Some(host) = host {
            self.hub.set_host(host);
        }
        self.keys_sent = 0;
        self.resume(rest);
    }

    fn resume(&mut self, rest: Vec<u8>) {
        self.awaiting_reconnect = false;
        // Bytes that arrived while waiting come after what followed the
        // RECONNECT.
        let later = self.decoder.take_pending();
        self.decoder.feed(&rest);
        self.decoder.feed(&later);
        self.pump();
    }

    /// A reconnecting host takes this session over from `peer_ip`: the
    /// previous host connection is closed and `rest` (what the new host
    /// sent after RECONNECT) is decoded as if it had come on the old one.
    pub fn adopt_host(
        &mut self,
        host: Peer,
        peer_ip: String,
        client_version: String,
        rest: Vec<u8>,
    ) {
        info!(peer = %peer_ip, token = %self.short_token(), "host reconnected to a live session");
        self.hub.host_adopted(host);
        self.peer_ip = peer_ip;
        self.client_version = Some(client_version);
        self.closed = false;
        self.awaiting_reconnect = false;
        self.decoder = Decoder::new();
        self.host_data(&rest);
    }

    pub fn peer_ip(&self) -> &str {
        &self.peer_ip
    }

    /// A viewer joined. With a backend it is announced there
    /// (`tmate_notify_client_join`), which is what produces the host's
    /// notice and client count.
    pub fn attach_viewer(
        &mut self,
        id: ViewerId,
        peer: Peer,
        access: Access,
        ip: &str,
        pubkey: Option<&str>,
        size: Size,
    ) {
        self.hub.attach_viewer(id, peer, access, ip, size);
        if self.backend && !self.closed && !self.hub.is_ended() {
            let mut enc = Encoder::new();
            backend::encode_client_join(
                &mut enc,
                id.raw() as i64,
                ip,
                pubkey,
                access == Access::ReadOnly,
            );
            self.control.backend_send(enc.take());
            self.announced.insert(id);
        }
    }

    pub fn detach_viewer(&mut self, id: ViewerId) {
        self.hub.detach_viewer(id);
        if self.announced.remove(&id) && !self.closed {
            let mut enc = Encoder::new();
            backend::encode_client_left(&mut enc, id.raw() as i64);
            self.control.backend_send(enc.take());
        }
    }

    pub fn resize_viewer(&self, id: ViewerId, size: Size) {
        self.hub.resize_viewer(id, size);
    }

    /// Returns the generation to pass to `flush_viewer` when an ESC is held.
    pub fn viewer_input(&self, id: ViewerId, data: &[u8]) -> Option<u64> {
        self.hub.viewer_input(id, data)
    }

    pub fn flush_viewer(&self, id: ViewerId, generation: u64) {
        self.hub.flush_viewer(id, generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::Payload;
    use crate::msgpack::{Decoder, Value};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<String>>,
        backend: Mutex<Vec<u8>>,
    }

    impl Control for Arc<Recorder> {
        fn register(&self, tokens: &Tokens) {
            self.events
                .lock()
                .unwrap()
                .push(format!("register {}", &tokens.rw[..4]));
        }
        fn unregister(&self, tokens: &Tokens) {
            self.events
                .lock()
                .unwrap()
                .push(format!("unregister {}", &tokens.rw[..4]));
        }
        fn authorized_keys(&self, enabled: bool, keys: &[PublicKey]) {
            self.events
                .lock()
                .unwrap()
                .push(format!("keys {enabled} {}", keys.len()));
        }
        fn reconnection_data(&self, _tokens: &Tokens) -> String {
            "signed".into()
        }
        fn reconnect(&self, data: String, rest: Vec<u8>, client_version: String) {
            self.events.lock().unwrap().push(format!(
                "reconnect {data} rest={} v={client_version}",
                rest.len()
            ));
        }
        fn backend_send(&self, data: Vec<u8>) {
            self.backend.lock().unwrap().extend_from_slice(&data);
        }
        fn backend_close(&self) {
            self.events.lock().unwrap().push("backend_close".into());
        }
    }

    impl Recorder {
        /// Everything sent to the backend so far, decoded.
        fn backend_msgs(&self) -> Vec<Value> {
            let mut dec = Decoder::new();
            dec.feed(&std::mem::take(&mut *self.backend.lock().unwrap()));
            let mut out = Vec::new();
            while let Some(v) = dec.next_value().unwrap() {
                out.push(v);
            }
            out
        }
    }

    fn s(text: &str) -> Value {
        Value::Bytes(text.as_bytes().to_vec())
    }

    fn header() -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(3).int(0).int(PROTOCOL_VERSION).str("2.4.0");
        enc.take()
    }

    fn ready() -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(1).int(9); // READY
        enc.take()
    }

    fn driver(ctl: Arc<Recorder>) -> (Driver, hub::PeerRx) {
        driver_with(ctl, false)
    }

    fn driver_with(ctl: Arc<Recorder>, backend: bool) -> (Driver, hub::PeerRx) {
        let (host, rx) = Peer::new();
        let adv = Arc::new(Advertised {
            host: "h".into(),
            port: 2200,
        });
        (
            Driver::new(
                Config {
                    tokens: Tokens::generate(),
                    keys_required: false,
                    peer_ip: "1.2.3.4".into(),
                    host_pubkey: None,
                    advertised: adv,
                    backend,
                },
                host,
                Box::new(ctl),
            ),
            rx,
        )
    }

    fn drain(rx: &mut hub::PeerRx) -> (Vec<Value>, bool) {
        let mut dec = Decoder::new();
        let mut closed = false;
        while let Some(p) = rx.try_recv() {
            match p {
                Payload::Data(d) => dec.feed(&d),
                Payload::Close => closed = true,
            }
        }
        let mut out = Vec::new();
        while let Some(v) = dec.next_value().unwrap() {
            out.push(v);
        }
        (out, closed)
    }

    #[test]
    fn handshake_registers_and_fin_unregisters() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver(ctl.clone());
        d.host_data(&header());
        d.host_data(&ready());
        let (msgs, closed) = drain(&mut rx);
        assert!(!closed);
        // notify, notify, set_env, notify, set_env, set_env, set_env, ready
        assert_eq!(msgs.len(), 8);
        assert_eq!(
            ctl.events.lock().unwrap().as_slice(),
            ["register ".to_string() + &d.tokens().rw[..4]]
        );
        let mut enc = Encoder::new();
        enc.array(1).int(8); // FIN
        d.host_data(&enc.take());
        let (_, closed) = drain(&mut rx);
        assert!(closed);
        assert!(d.is_closed());
        assert_eq!(ctl.events.lock().unwrap().len(), 2);
        assert!(ctl.events.lock().unwrap()[1].starts_with("unregister"));
    }

    #[test]
    fn protocol_mismatch_and_garbage_cut_the_host_off() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver(ctl.clone());
        let mut enc = Encoder::new();
        enc.array(3).int(0).int(5).str("2.3.0");
        d.host_data(&enc.take());
        let (msgs, closed) = drain(&mut rx);
        assert!(closed);
        assert_eq!(msgs.len(), 1, "a notice explains before the close");
        assert!(d.is_closed());
        assert!(ctl.events.lock().unwrap().is_empty(), "never registered");

        let (mut d, mut rx) = driver(ctl.clone());
        d.host_data(&[0x80]); // a map: not accepted
        assert!(d.is_closed());
        assert!(drain(&mut rx).1);
        // Bytes after the failure are ignored.
        d.host_data(&header());
        assert!(drain(&mut rx).0.is_empty());
    }

    #[test]
    fn reconnect_pauses_decoding_until_the_gateway_answers() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver(ctl.clone());
        let mut enc = Encoder::new();
        enc.array(2).int(10).str("blob|sig"); // RECONNECT
        let mut bytes = header();
        bytes.extend(enc.take());
        bytes.extend(ready());
        d.host_data(&bytes);
        let events = ctl.events.lock().unwrap().clone();
        assert_eq!(
            events,
            [format!("reconnect blob|sig rest={} v=2.4.0", ready().len())]
        );
        assert!(drain(&mut rx).0.is_empty(), "READY was not processed yet");
        // More bytes queue up meanwhile.
        d.host_data(&[0x91, 0x08]); // FIN
        assert!(drain(&mut rx).0.is_empty());
        let fresh = Tokens::generate();
        d.reconnect_fresh(fresh.clone(), ready());
        let (msgs, closed) = drain(&mut rx);
        assert!(closed, "the queued FIN was processed after READY");
        assert!(msgs.len() >= 6);
        assert_eq!(d.tokens(), &fresh);
        let events = ctl.events.lock().unwrap().clone();
        assert!(
            events
                .iter()
                .any(|e| *e == format!("register {}", &fresh.rw[..4])),
            "{events:?}"
        );
    }

    #[test]
    fn rejected_reconnect_continues_as_a_new_session() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver(ctl.clone());
        let original = d.tokens().clone();
        let mut enc = Encoder::new();
        enc.array(2).int(10).str("garbage");
        let mut bytes = header();
        bytes.extend(enc.take());
        d.host_data(&bytes);
        d.reconnect_rejected(ready());
        assert_eq!(d.tokens(), &original);
        assert_eq!(drain(&mut rx).0.len(), 8);
    }

    #[test]
    fn key_list_changes_reach_the_control_before_registration() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, _rx) = driver(ctl.clone());
        d.host_data(&header());
        let mut enc = Encoder::new();
        // EXEC_CMD set-option -g tmate-authorized-keys /x
        enc.array(5)
            .int(12)
            .str("set-option")
            .str("-g")
            .str("tmate-authorized-keys")
            .str("/x");
        d.host_data(&enc.take());
        d.host_data(&ready());
        let events = ctl.events.lock().unwrap().clone();
        assert_eq!(events[0], "keys true 0");
        assert!(events[1].starts_with("register"));
    }

    fn ctl_msg(items: Vec<Value>) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.value(&Value::Array(items));
        enc.take()
    }

    #[test]
    fn with_a_backend_the_header_goes_there_and_nothing_is_said_locally() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver_with(ctl.clone(), true);
        d.host_data(&header());
        let tokens = d.tokens().clone();
        let msgs = ctl.backend_msgs();
        assert_eq!(
            msgs[0],
            Value::Array(vec![
                Value::Int(0),
                Value::Int(2),
                s("1.2.3.4"),
                Value::Nil,
                s(&tokens.rw),
                s(&tokens.ro),
                s("ssh -p2200 %s@h"),
                s("2.4.0"),
                Value::Int(6),
            ]),
            "CTL_HEADER first"
        );
        let mut dec = Decoder::new();
        dec.feed(&header());
        let host_header = dec.next_value().unwrap().unwrap();
        assert_eq!(
            msgs[1],
            Value::Array(vec![Value::Int(1), host_header]),
            "then the host's HEADER forwarded verbatim"
        );
        assert_eq!(msgs.len(), 2);

        d.host_data(&ready());
        let (to_host, closed) = drain(&mut rx);
        assert!(!closed);
        assert!(
            to_host.is_empty(),
            "notices, SET_ENV and READY come from the backend: {to_host:?}"
        );
        let msgs = ctl.backend_msgs();
        assert_eq!(
            msgs,
            vec![Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![Value::Int(9)])
            ])]
        );
        assert_eq!(
            ctl.events.lock().unwrap().as_slice(),
            [format!("register {}", &tokens.rw[..4])]
        );

        // What the backend forwards reaches the host as is.
        let notice = Value::Array(vec![Value::Int(0), s("web session: http://x/t/abc")]);
        let set_env = Value::Array(vec![Value::Int(4), s("tmate_web"), s("http://x/t/abc")]);
        let mut bytes = ctl_msg(vec![Value::Int(0), notice.clone()]);
        bytes.extend(ctl_msg(vec![Value::Int(0), set_env.clone()]));
        bytes.extend(ctl_msg(vec![
            Value::Int(0),
            Value::Array(vec![Value::Int(5)]),
        ]));
        // Split anywhere: the backend stream is decoded incrementally.
        d.backend_data(&bytes[..5]);
        d.backend_data(&bytes[5..]);
        let (to_host, _) = drain(&mut rx);
        assert_eq!(
            to_host,
            vec![notice, set_env, Value::Array(vec![Value::Int(5)])]
        );
    }

    #[test]
    fn backend_keys_resize_snapshot_and_rename() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver_with(ctl.clone(), true);
        d.host_data(&header());
        d.host_data(&ready());
        let old = d.tokens().clone();
        ctl.backend_msgs();
        ctl.events.lock().unwrap().clear();

        // A layout and some output, so there is something to snapshot.
        let mut enc = Encoder::new();
        enc.array(5).int(1).int(80).int(23);
        enc.array(1)
            .array(4)
            .int(0)
            .str("bash")
            .array(1)
            .array(5)
            .int(0)
            .int(80)
            .int(23)
            .int(0)
            .int(0);
        enc.int(0);
        enc.int(0);
        enc.array(3).int(2).int(0).bin(b"hello");
        d.host_data(&enc.take());
        let forwarded = ctl.backend_msgs();
        assert_eq!(
            forwarded.len(),
            2,
            "layout and pty data forwarded: {forwarded:?}"
        );
        assert_eq!(
            forwarded[1].as_array().unwrap()[1].as_array().unwrap()[2],
            s("hello")
        );
        drain(&mut rx);

        d.backend_data(&ctl_msg(vec![Value::Int(2), Value::Int(-1), s("ab")]));
        let (to_host, _) = drain(&mut rx);
        assert_eq!(
            to_host,
            vec![
                Value::Array(vec![Value::Int(6), Value::Int(-1), Value::Int(97)]),
                Value::Array(vec![Value::Int(6), Value::Int(-1), Value::Int(98)]),
            ],
            "PANE_KEYS: one PANE_KEY per byte"
        );

        d.backend_data(&ctl_msg(vec![
            Value::Int(3),
            Value::Int(60),
            Value::Int(20),
        ]));
        let (to_host, _) = drain(&mut rx);
        assert_eq!(
            to_host,
            vec![Value::Array(vec![
                Value::Int(2),
                Value::Int(60),
                Value::Int(20)
            ])],
            "RESIZE reaches the host through the size rule"
        );

        d.backend_data(&ctl_msg(vec![Value::Int(1), Value::Int(300)]));
        let snap = ctl.backend_msgs();
        assert_eq!(snap.len(), 1);
        let snap = snap[0].as_array().unwrap();
        assert_eq!(snap[0], Value::Int(2));
        let pane = snap[1].as_array().unwrap()[0].as_array().unwrap();
        assert_eq!(pane[0], Value::Int(0));
        assert_eq!(pane[1], Value::Array(vec![Value::Int(5), Value::Int(0)]));
        let first_line = pane[3].as_array().unwrap()[0].as_array().unwrap();
        assert_eq!(first_line[0], s("hello"));
        assert_eq!(first_line[1].as_array().unwrap().len(), 5);

        let renamed = Tokens {
            rw: "acme/demo".into(),
            ro: "ro-acme/demo".into(),
        };
        d.backend_data(&ctl_msg(vec![
            Value::Int(5),
            s(&renamed.rw),
            s(&renamed.ro),
        ]));
        assert_eq!(d.tokens(), &renamed);
        assert_eq!(
            ctl.events.lock().unwrap().as_slice(),
            [
                format!("unregister {}", &old.rw[..4]),
                "register acme".to_string()
            ]
        );
        // Garbage from the backend is ignored; a broken stream ends the session.
        d.backend_data(&ctl_msg(vec![Value::Int(42)]));
        assert!(!d.is_closed());
        d.backend_data(&[0x80]);
        assert!(d.is_closed());
        assert!(drain(&mut rx).1, "the host was closed");
        assert!(
            ctl.events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e == "backend_close")
        );
    }

    #[test]
    fn viewers_are_announced_to_the_backend_and_fin_is_forwarded_before_closing() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, _rx) = driver_with(ctl.clone(), true);
        d.host_data(&header());
        d.host_data(&ready());
        ctl.backend_msgs();
        let (peer, _vrx) = Peer::new();
        let id = ViewerId::from_raw(3);
        d.attach_viewer(
            id,
            peer,
            Access::ReadOnly,
            "10.0.0.9",
            Some("ssh-ed25519 AAAA"),
            Size { cols: 80, rows: 24 },
        );
        assert_eq!(
            ctl.backend_msgs(),
            vec![Value::Array(vec![
                Value::Int(3),
                Value::Int(3),
                s("10.0.0.9"),
                s("ssh-ed25519 AAAA"),
                Value::Bool(true)
            ])]
        );
        d.detach_viewer(id);
        d.detach_viewer(ViewerId::from_raw(99));
        assert_eq!(
            ctl.backend_msgs(),
            vec![Value::Array(vec![Value::Int(4), Value::Int(3)])],
            "only announced viewers are reported gone"
        );
        d.host_data(&[0x91, 0x08]); // FIN
        assert_eq!(
            ctl.backend_msgs(),
            vec![Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![Value::Int(8)])
            ])]
        );
        let events = ctl.events.lock().unwrap().clone();
        assert_eq!(events.last().map(String::as_str), Some("backend_close"));
        assert!(events.iter().any(|e| e.starts_with("unregister")));
    }

    #[test]
    fn losing_the_backend_ends_the_session() {
        let ctl = Arc::new(Recorder::default());
        let (mut d, mut rx) = driver_with(ctl.clone(), true);
        d.host_data(&header());
        d.host_data(&ready());
        d.backend_gone();
        assert!(d.is_closed());
        assert!(drain(&mut rx).1);
        // With a backend, RECONNECT is its business: no pause, no gateway.
        let (mut d, _rx) = driver_with(ctl.clone(), true);
        let mut enc = Encoder::new();
        enc.array(2).int(10).str("backend-signed");
        let mut bytes = header();
        bytes.extend(enc.take());
        bytes.extend(ready());
        d.host_data(&bytes);
        assert!(
            !ctl.events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("reconnect"))
        );
        let msgs = ctl.backend_msgs();
        assert!(msgs.iter().any(|m| {
            m.as_array()
                .map(|a| a[1] == Value::Array(vec![Value::Int(10), s("backend-signed")]))
                == Some(true)
        }));
    }
}
