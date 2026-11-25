//! Passwords and guess limiting for the web portal.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

pub const MIN_PASSWORD: usize = 10;
pub const MAX_PASSWORD: usize = 1024;

/// Argon2id with 19 MiB and 2 passes (the OWASP recommendation).
fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).expect("valid params"),
    )
}

pub fn check_password_rules(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD {
        bail!("passwords are at least {MIN_PASSWORD} characters");
    }
    if pw.len() > MAX_PASSWORD {
        bail!("passwords are at most {MAX_PASSWORD} bytes");
    }
    Ok(())
}

/// Hash a password to a PHC string. Slow on purpose: call it off the async
/// runtime (`spawn_blocking`).
pub fn hash_password(pw: &str) -> Result<String> {
    check_password_rules(pw)?;
    Ok(argon2()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

/// Check a password against a PHC string. With `None` (no such account, or
/// no password), a dummy hash is checked instead, so the answer takes the
/// same time either way, and is `false`.
pub fn verify_password(pw: &str, hash: Option<&str>) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| hash_password("dummy-password-for-timing").unwrap());
    let (h, real) = match hash {
        Some(h) => (h, true),
        None => (dummy.as_str(), false),
    };
    if pw.len() > MAX_PASSWORD {
        return false;
    }
    let ok = PasswordHash::new(h)
        .map(|p| argon2().verify_password(pw.as_bytes(), &p).is_ok())
        .unwrap_or(false);
    ok && real
}

/// A token bucket per key: `burst` tries, then one every `every`.
pub struct Limiter {
    burst: f64,
    every: Duration,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(burst: u32, every: Duration) -> Self {
        Limiter {
            burst: burst as f64,
            every,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one try for `key`. `false`: too many, wait.
    pub fn take(&self, key: &str) -> bool {
        self.take_at(key, Instant::now())
    }

    fn take_at(&self, key: &str, now: Instant) -> bool {
        let mut b = self.buckets.lock().unwrap();
        if b.len() > 100_000 {
            // Forget buckets that have refilled.
            let full = self.every.mul_f64(self.burst);
            b.retain(|_, (_, t)| now.duration_since(*t) < full);
        }
        let (tokens, last) = b.entry(key.to_string()).or_insert((self.burst, now));
        let refill = now.duration_since(*last).as_secs_f64() / self.every.as_secs_f64();
        *tokens = (*tokens + refill).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The key guesses from one client are counted under: an IPv4 address, or
/// an IPv6 /64 (one subscriber usually gets a whole /64).
pub fn client_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", Some(&h)));
        assert!(!verify_password("wrong horse battery", Some(&h)));
        assert!(!verify_password("correct horse battery", None));
        assert!(hash_password("short").is_err());
    }

    #[test]
    fn limiter_refills() {
        let l = Limiter::new(3, Duration::from_secs(6));
        let t = Instant::now();
        assert!((0..3).all(|_| l.take_at("a", t)));
        assert!(!l.take_at("a", t));
        assert!(l.take_at("b", t), "separate keys");
        assert!(!l.take_at("a", t + Duration::from_secs(3)));
        assert!(l.take_at("a", t + Duration::from_secs(7)));
    }

    #[test]
    fn client_keys() {
        assert_eq!(client_key("10.0.0.1".parse().unwrap()), "10.0.0.1");
        assert_eq!(client_key("2001:db8:1:2:3:4:5:6".parse().unwrap()), "2001:db8:1:2::/64");
        assert_eq!(client_key("::ffff:10.0.0.1".parse().unwrap()), "10.0.0.1");
    }
}
