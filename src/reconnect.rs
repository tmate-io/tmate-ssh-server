//! Reconnection data: what a host is handed at READY as the
//! `tmate_reconnection_data` environment variable and sends back in
//! `RECONNECT` when its connection drops. It names the session's tokens
//! and is signed with an HMAC over a key generated at startup, so only
//! this server process can mint data it will accept; after a restart every
//! session is new, as it was with the old server without a backend.
//!
//! Format, as the Elixir backend's `pack_and_sign!`: `base64(payload)|base64(hmac)`.

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::session::{self, Tokens};

type HmacSha256 = Hmac<Sha256>;

fn key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::fill(&mut k);
        k
    })
}

fn mac(payload: &[u8]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key()).expect("any key length works for HMAC");
    m.update(payload);
    m
}

/// Signed data naming `tokens`.
pub fn data_for(tokens: &Tokens) -> String {
    let payload = format!("1:{}:{}", tokens.rw, tokens.ro);
    let sig = mac(payload.as_bytes()).finalize().into_bytes();
    format!("{}|{}", B64.encode(payload.as_bytes()), B64.encode(sig))
}

/// The tokens named by `data`, if this process signed it.
pub fn verify(data: &str) -> Option<Tokens> {
    let (payload, sig) = data.split_once('|')?;
    let payload = B64.decode(payload).ok()?;
    let sig = B64.decode(sig).ok()?;
    mac(&payload).verify_slice(&sig).ok()?;
    let payload = std::str::from_utf8(&payload).ok()?;
    let mut parts = payload.split(':');
    if parts.next()? != "1" {
        return None;
    }
    let rw = parts.next()?.to_string();
    let ro = parts.next()?.to_string();
    if parts.next().is_some()
        || !session::is_valid_token(&rw)
        || !session::is_valid_token(&ro)
        || !ro.starts_with("ro-")
    {
        return None;
    }
    Some(Tokens { rw, ro })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let tokens = Tokens::generate();
        let data = data_for(&tokens);
        let back = verify(&data).unwrap();
        assert_eq!((back.rw, back.ro), (tokens.rw.clone(), tokens.ro.clone()));

        assert!(verify("").is_none());
        assert!(verify("garbage|garbage").is_none());
        let (payload, sig) = data.split_once('|').unwrap();
        let other = Tokens::generate();
        let forged = format!(
            "{}|{sig}",
            B64.encode(format!("1:{}:{}", other.rw, other.ro))
        );
        assert!(
            verify(&forged).is_none(),
            "payload swapped under a valid signature"
        );
        assert!(verify(&format!("{payload}|{}", B64.encode([0u8; 32]))).is_none());
        // Unsigned-looking tokens that are not valid tokens are refused even if signed.
        let bad = format!("1:{}:{}", "short", tokens.ro);
        let sig = B64.encode(mac(bad.as_bytes()).finalize().into_bytes());
        assert!(verify(&format!("{}|{sig}", B64.encode(bad))).is_none());
    }
}
