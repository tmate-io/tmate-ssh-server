//! Session tokens and the registry mapping tokens to live sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::link::SessionHandle;

/// Characters used in session tokens; letters that are easy to confuse
/// when read aloud are left out, matching the original server.
const TOKEN_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
pub const TOKEN_LEN: usize = 25;
const RO_PREFIX: &str = "ro-";

pub fn random_token() -> String {
    (0..TOKEN_LEN)
        .map(|_| TOKEN_ALPHABET[rand::random_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}

/// Usernames that viewers may present. Anything else is rejected before
/// the registry is consulted.
pub fn is_valid_token(s: &str) -> bool {
    let body = s.strip_prefix(RO_PREFIX).unwrap_or(s);
    body.len() == TOKEN_LEN && body.bytes().all(|b| TOKEN_ALPHABET.contains(&b))
}

/// Longest token accepted from a backend or a viewer in backend mode.
pub const MAX_NAMED_TOKEN_LEN: usize = 128;

/// The old server's `tmate_validate_session_token`: what a username may
/// look like when a backend names sessions (`prefix/name`, hyphens):
/// more than two characters from `[A-Za-z0-9-_/]`. Random tokens pass
/// too. Used wherever a backend is involved; without one, only
/// `is_valid_token` names a session.
pub fn is_acceptable_token(s: &str) -> bool {
    s.len() > 2
        && s.len() <= MAX_NAMED_TOKEN_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'/')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub rw: String,
    pub ro: String,
}

impl Tokens {
    pub fn generate() -> Self {
        Tokens {
            rw: random_token(),
            ro: format!("{RO_PREFIX}{}", random_token()),
        }
    }
}

/// How a viewer's username resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadWrite,
    ReadOnly,
}

/// Sessions viewers can join. A session is listed only once its host is
/// ready, so its authorized keys are known before anyone can try them.
#[derive(Default)]
pub struct Registry {
    by_token: Mutex<HashMap<String, (Arc<SessionHandle>, Access)>>,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Arc<SessionHandle>, Access)>> {
        self.by_token.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lists `tokens` for `session`. Returns false, changing nothing, when
    /// either token is already held by a different live session: a worker
    /// (or a backend rename) must not be able to take over someone else's
    /// link by naming their token.
    pub fn insert(&self, tokens: &Tokens, session: Arc<SessionHandle>) -> bool {
        let mut map = self.map();
        let taken = [&tokens.rw, &tokens.ro]
            .into_iter()
            .any(|t| map.get(t).is_some_and(|(s, _)| !Arc::ptr_eq(s, &session)));
        if taken {
            return false;
        }
        map.insert(tokens.rw.clone(), (session.clone(), Access::ReadWrite));
        map.insert(tokens.ro.clone(), (session, Access::ReadOnly));
        true
    }

    /// Removes `tokens` only while they still point at `session`, so a
    /// superseded connection's cleanup cannot unlist the session that
    /// took over its tokens.
    pub fn remove_if(&self, tokens: &Tokens, session: &Arc<SessionHandle>) {
        let mut map = self.map();
        for token in [&tokens.rw, &tokens.ro] {
            if map.get(token).is_some_and(|(s, _)| Arc::ptr_eq(s, session)) {
                map.remove(token);
            }
        }
    }

    pub fn lookup(&self, token: &str) -> Option<(Arc<SessionHandle>, Access)> {
        self.map().get(token).cloned()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map().len() / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_valid_and_distinct() {
        let t = Tokens::generate();
        assert!(is_valid_token(&t.rw));
        assert!(is_valid_token(&t.ro));
        assert_ne!(t.rw, t.ro);
        assert!(!is_valid_token("tmate"));
        assert!(!is_valid_token("../etc/passwd"));
        assert!(!is_valid_token(&"a".repeat(TOKEN_LEN - 1)));
        assert!(is_acceptable_token(&t.rw) && is_acceptable_token(&t.ro));
        assert!(is_acceptable_token("acme/my-session"));
        assert!(is_acceptable_token("ro-acme/my-session_2"));
        assert!(!is_acceptable_token("ab"));
        assert!(!is_acceptable_token("../etc/passwd"));
        assert!(!is_acceptable_token("has space"));
        assert!(!is_acceptable_token(&"a".repeat(MAX_NAMED_TOKEN_LEN + 1)));
    }

    #[tokio::test]
    async fn registry_roundtrip_and_conditional_removal() {
        use crate::limits::{SessionCounter, SessionLimits};
        let r = Registry::new();
        let env = crate::link::Env {
            registry: r.clone(),
            advertised: Arc::new(crate::driver::Advertised {
                host: "h".into(),
                port: 1,
            }),
            keys_required: false,
            mode: crate::link::Mode::InProcess,
            backend: None,
            sessions_dir: None,
        };
        let counter = SessionCounter::new(SessionLimits {
            per_ip: 10,
            total: 10,
        });
        let make = || {
            SessionHandle::start(
                &env,
                "1.1.1.1".into(),
                None,
                crate::hub::Peer::new().0,
                counter.acquire(None).unwrap(),
                None,
            )
        };
        let a = make();
        let b = make();
        let tokens = Tokens::generate();
        assert!(r.insert(&tokens, a.clone()));
        assert!(
            !r.insert(&tokens, b.clone()),
            "another session cannot take over a listed token"
        );
        assert!(
            r.insert(&tokens, a.clone()),
            "the owner may re-list its tokens"
        );
        assert_eq!(r.lookup(&tokens.rw).unwrap().1, Access::ReadWrite);
        assert_eq!(r.lookup(&tokens.ro).unwrap().1, Access::ReadOnly);
        assert_eq!(r.len(), 1);
        r.remove_if(&tokens, &b);
        assert!(
            r.lookup(&tokens.rw).is_some(),
            "another session's cleanup leaves the entry"
        );
        r.remove_if(&tokens, &a);
        assert!(r.lookup(&tokens.rw).is_none());
        assert_eq!(r.len(), 0);
    }
}
