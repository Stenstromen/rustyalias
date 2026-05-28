use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-client-IP fixed-window rate limiter.
///
/// Cloning is cheap: the inner state is shared via an `Arc`, so each clone
/// (e.g. the one handed to the UDP thread) sees the same counters.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    window: Duration,
    max_requests: u32,
    state: Mutex<HashMap<IpAddr, Bucket>>,
}

struct Bucket {
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    /// Build a new limiter. Pass `0` for either argument to disable rate
    /// limiting entirely (every request is allowed).
    pub fn new(window_seconds: u64, max_requests: u32) -> Self {
        Self {
            inner: Arc::new(Inner {
                window: Duration::from_secs(window_seconds),
                max_requests,
                state: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.max_requests > 0 && !self.inner.window.is_zero()
    }

    /// Returns `true` if the request from `ip` is allowed, `false` if it
    /// should be dropped because the client exceeded its quota for the
    /// current window.
    pub fn check(&self, ip: IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }

        let now = Instant::now();
        let mut state = match self.inner.state.lock() {
            Ok(guard) => guard,
            // A poisoned mutex would only happen if a previous holder panicked.
            // Fail open so a logic bug doesn't take the whole resolver down.
            Err(poisoned) => poisoned.into_inner(),
        };

        // Opportunistic pruning so the map can't grow unbounded over time.
        if state.len() > 1024 {
            let window = self.inner.window;
            state.retain(|_, bucket| now.duration_since(bucket.window_start) < window);
        }

        let bucket = state.entry(ip).or_insert(Bucket {
            window_start: now,
            count: 0,
        });

        if now.duration_since(bucket.window_start) >= self.inner.window {
            bucket.window_start = now;
            bucket.count = 1;
            return true;
        }

        if bucket.count >= self.inner.max_requests {
            return false;
        }

        bucket.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn disabled_when_either_value_is_zero() {
        let zero_requests = RateLimiter::new(60, 0);
        let zero_window = RateLimiter::new(0, 10);
        for _ in 0..1000 {
            assert!(zero_requests.check(ip(1)));
            assert!(zero_window.check(ip(1)));
        }
    }

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let rl = RateLimiter::new(60, 3);
        assert!(rl.check(ip(1)));
        assert!(rl.check(ip(1)));
        assert!(rl.check(ip(1)));
        assert!(!rl.check(ip(1)));
        assert!(!rl.check(ip(1)));
    }

    #[test]
    fn limits_are_tracked_per_ip() {
        let rl = RateLimiter::new(60, 1);
        assert!(rl.check(ip(1)));
        assert!(!rl.check(ip(1)));
        assert!(rl.check(ip(2)));
        assert!(!rl.check(ip(2)));
    }

    #[test]
    fn window_resets_after_elapsing() {
        let rl = RateLimiter::new(1, 2);
        assert!(rl.check(ip(1)));
        assert!(rl.check(ip(1)));
        assert!(!rl.check(ip(1)));
        sleep(Duration::from_millis(1100));
        assert!(rl.check(ip(1)));
    }
}
