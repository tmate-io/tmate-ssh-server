//! Resource limits the gateway applies to hosts: how many sessions one
//! source address and the whole server may hold, and how fast a host may
//! send. Viewer output queues are bounded in `hub::Peer`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SessionLimits {
    pub per_ip: usize,
    pub total: usize,
}

#[derive(Debug)]
struct Counts {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

/// Why a session was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    PerIp(usize),
    Total(usize),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::PerIp(n) => write!(f, "too many sessions from your address (limit {n})"),
            Refusal::Total(n) => write!(f, "the server is full ({n} sessions)"),
        }
    }
}

/// Counts live sessions. `acquire` hands out a guard that releases its
/// slot when dropped.
pub struct SessionCounter {
    limits: SessionLimits,
    counts: Mutex<Counts>,
}

pub struct SessionGuard {
    counter: Arc<SessionCounter>,
    ip: Option<IpAddr>,
}

impl SessionCounter {
    pub fn new(limits: SessionLimits) -> Arc<Self> {
        Arc::new(SessionCounter {
            limits,
            counts: Mutex::new(Counts {
                total: 0,
                by_ip: HashMap::new(),
            }),
        })
    }

    /// `ip` is `None` when the peer address is unknown (counted against
    /// the total only).
    pub fn acquire(self: &Arc<Self>, ip: Option<IpAddr>) -> Result<SessionGuard, Refusal> {
        let mut c = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if c.total >= self.limits.total {
            return Err(Refusal::Total(self.limits.total));
        }
        if let Some(ip) = ip {
            let n = c.by_ip.entry(ip).or_insert(0);
            if *n >= self.limits.per_ip {
                return Err(Refusal::PerIp(self.limits.per_ip));
            }
            *n += 1;
        }
        c.total += 1;
        Ok(SessionGuard {
            counter: self.clone(),
            ip,
        })
    }

    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut c = self
            .counter
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        c.total = c.total.saturating_sub(1);
        if let Some(ip) = self.ip
            && let Some(n) = c.by_ip.get_mut(&ip)
        {
            *n -= 1;
            if *n == 0 {
                c.by_ip.remove(&ip);
            }
        }
    }
}

/// Inbound rate limit for one host connection: bytes per second, measured
/// over one-second windows. The connection is dropped once it has been
/// over the limit for `patience` without a quiet second in between, so a
/// burst (a snapshot, a screenful of `cat`) passes and only a sustained
/// flood is cut.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    bytes_per_sec: usize,
    patience: Duration,
    window_start: Instant,
    in_window: usize,
    over_since: Option<Instant>,
}

impl RateLimiter {
    pub fn new(bytes_per_sec: usize, patience: Duration, now: Instant) -> Self {
        RateLimiter {
            bytes_per_sec,
            patience,
            window_start: now,
            in_window: 0,
            over_since: None,
        }
    }

    /// Records `n` bytes arriving at `now`; false means the limit was
    /// exceeded for too long and the connection should go.
    pub fn allow(&mut self, n: usize, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            // The window that just ended decides whether the flood went on.
            if self.in_window <= self.bytes_per_sec {
                self.over_since = None;
            }
            self.window_start = now;
            self.in_window = 0;
        }
        self.in_window = self.in_window.saturating_add(n);
        if self.in_window > self.bytes_per_sec {
            let since = *self.over_since.get_or_insert(now);
            if now.duration_since(since) >= self.patience {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_ip_and_total_limits_are_enforced_and_released() {
        let counter = SessionCounter::new(SessionLimits {
            per_ip: 2,
            total: 3,
        });
        let a1 = counter.acquire(Some(ip("10.0.0.1"))).unwrap();
        let _a2 = counter.acquire(Some(ip("10.0.0.1"))).unwrap();
        assert_eq!(
            counter.acquire(Some(ip("10.0.0.1"))).err(),
            Some(Refusal::PerIp(2))
        );
        let _b1 = counter.acquire(Some(ip("10.0.0.2"))).unwrap();
        assert_eq!(
            counter.acquire(Some(ip("10.0.0.3"))).err(),
            Some(Refusal::Total(3))
        );
        assert_eq!(counter.acquire(None).err(), Some(Refusal::Total(3)));
        drop(a1);
        assert_eq!(counter.total(), 2);
        let _a3 = counter.acquire(Some(ip("10.0.0.1"))).unwrap();
        assert_eq!(counter.total(), 3);
        // Unknown addresses count against the total only.
        let counter = SessionCounter::new(SessionLimits {
            per_ip: 1,
            total: 10,
        });
        let _u1 = counter.acquire(None).unwrap();
        let _u2 = counter.acquire(None).unwrap();
        assert_eq!(counter.total(), 2);
    }

    #[test]
    fn a_burst_passes_but_a_sustained_flood_is_cut() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(1000, Duration::from_secs(5), t0);
        // A big burst in one second is over the limit but tolerated.
        assert!(rl.allow(5000, t0));
        assert!(rl.allow(5000, t0 + Duration::from_millis(500)));
        // A quiet second resets the patience.
        assert!(rl.allow(10, t0 + Duration::from_millis(1100)));
        assert!(rl.allow(5000, t0 + Duration::from_millis(2200)));
        // Over the limit every second for five seconds: cut.
        let mut t = t0 + Duration::from_millis(2200);
        let mut cut = false;
        for _ in 0..12 {
            t += Duration::from_millis(1000);
            if !rl.allow(5000, t) {
                cut = true;
                break;
            }
        }
        assert!(cut, "a flood lasting longer than the patience is cut");
    }

    #[test]
    fn staying_under_the_limit_is_never_cut() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(1000, Duration::from_secs(5), t0);
        let mut t = t0;
        for _ in 0..600 {
            t += Duration::from_millis(100);
            assert!(rl.allow(99, t));
        }
    }

    #[test]
    fn flood_is_cut_after_patience_even_within_windows() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(1000, Duration::from_secs(5), t0);
        let mut t = t0;
        let mut allowed = 0;
        loop {
            t += Duration::from_millis(250);
            if !rl.allow(400, t) {
                break;
            }
            allowed += 1;
            assert!(allowed < 100, "never cut");
        }
        // 1600 B/s: over from the first second on; cut at about five seconds.
        assert!(
            t >= t0 + Duration::from_secs(5) && t <= t0 + Duration::from_secs(7),
            "{:?}",
            t - t0
        );
    }
}
