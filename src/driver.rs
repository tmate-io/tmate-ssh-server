//! Everything a session does with what its host sends: decoding the
//! msgpack stream, the handshake (HEADER, READY, FIN, RECONNECT) and feeding
//! the `Hub` with the rest. This is the code that touches untrusted bytes,
//! so it is written to run either in the gateway process (in-process mode)
//! or inside a sandboxed worker, with the few things that need the gateway
//! (the token registry, viewer authentication, reconnection data signed by
//! the gateway) behind the `Control` trait.

use std::sync::Arc;

use russh::keys::PublicKey;
use tracing::{debug, info, warn};

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
}

pub struct Driver {
    hub: Arc<Hub>,
    decoder: Decoder,
    peer_ip: String,
    advertised: Arc<Advertised>,
    keys_required: bool,
    client_version: Option<String>,
    registered: bool,
    /// Waiting for the gateway's verdict on RECONNECT; bytes queue up.
    awaiting_reconnect: bool,
    /// The host connection was closed (by us or by it); nothing more is
    /// decoded. Adoption by a reconnecting host reopens it.
    closed: bool,
    keys_sent: u64,
    control: Box<dyn Control>,
}

impl Driver {
    pub fn new(
        tokens: Tokens,
        keys_required: bool,
        peer_ip: String,
        advertised: Arc<Advertised>,
        host: Peer,
        control: Box<dyn Control>,
    ) -> Driver {
        let hub = Hub::new(tokens, keys_required);
        hub.set_host(host);
        Driver {
            hub,
            decoder: Decoder::new(),
            peer_ip,
            advertised,
            keys_required,
            client_version: None,
            registered: false,
            awaiting_reconnect: false,
            closed: false,
            keys_sent: 0,
            control,
        }
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    pub fn tokens(&self) -> &Tokens {
        &self.hub.tokens
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
    /// connection closes, or a RECONNECT needs the gateway.
    fn pump(&mut self) {
        while !self.closed && !self.awaiting_reconnect {
            let value = match self.decoder.next_value() {
                Ok(Some(v)) => v,
                Ok(None) => break,
                Err(e) => return self.fail(&format!("bad msgpack from host: {e}")),
            };
            let msg = match HostMsg::parse(&value) {
                Ok(m) => m,
                Err(e) => return self.fail(&format!("bad message from host: {e}")),
            };
            self.on_host_msg(msg);
            self.sync_keys();
        }
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
            self.control.unregister(&self.hub.tokens);
            self.registered = false;
            info!(peer = %self.peer_ip, "host session closed");
        }
        self.hub.end();
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
                let rw = self.advertised.ssh_command(&self.hub.tokens.rw);
                let ro = self.advertised.ssh_command(&self.hub.tokens.ro);
                // A reconnected host already has its links; it is told so
                // instead, as the Elixir backend did.
                let reconnected = self.hub.take_reconnected();
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
                    &self.control.reconnection_data(&self.hub.tokens),
                );
                proto::encode_ready(&mut enc);
                self.hub.send_host(enc.take().into());
                if !self.registered {
                    // The key list must be known before anyone can join.
                    self.sync_keys();
                    self.control.register(&self.hub.tokens);
                    self.registered = true;
                }
                self.hub.host_ready();
                info!(peer = %self.peer_ip, token = %&self.hub.tokens.rw[..4], reconnected, "session ready");
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
        self.hub = Hub::new_reconnected(tokens, self.keys_required);
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
        info!(peer = %peer_ip, token = %&self.hub.tokens.rw[..4], "host reconnected to a live session");
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

    pub fn attach_viewer(&self, id: ViewerId, peer: Peer, access: Access, ip: &str, size: Size) {
        self.hub.attach_viewer(id, peer, access, ip, size);
    }

    pub fn detach_viewer(&self, id: ViewerId) {
        self.hub.detach_viewer(id);
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
        let (host, rx) = Peer::new();
        let adv = Arc::new(Advertised {
            host: "h".into(),
            port: 2200,
        });
        (
            Driver::new(
                Tokens::generate(),
                false,
                "1.2.3.4".into(),
                adv,
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
}
