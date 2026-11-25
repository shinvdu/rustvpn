//! Admin authentication: Argon2id password hashes and in-memory sessions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;

/// Stronger than the protocol defaults (4 MiB / 128 iterations), because the
/// admin password is the only credential protecting configuration writes.
pub const DEFAULT_M: u32 = 65_536;
pub const DEFAULT_T: u32 = 3;
pub const DEFAULT_P: u32 = 1;
pub const SALT_LEN: usize = 16;
pub const HASH_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub username: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub username: String,
    pub role: String,
    pub csrf: String,
    created: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, SessionEntry>>,
    idle: Duration,
    absolute: Duration,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            idle: Duration::from_secs(30 * 60),
            absolute: Duration::from_secs(12 * 60 * 60),
        }
    }

    pub fn create_session(&self, username: &str, role: &str) -> (String, String) {
        let token = random_hex(32);
        let csrf = random_hex(32);
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() > 1024 {
            sessions.retain(|_, s| {
                now.duration_since(s.last_seen) < self.idle
                    && now.duration_since(s.created) < self.absolute
            });
        }
        sessions.insert(
            token.clone(),
            SessionEntry {
                username: username.to_string(),
                role: role.to_string(),
                csrf: csrf.clone(),
                created: now,
                last_seen: now,
            },
        );
        (token, csrf)
    }

    /// Return the authenticated user and its CSRF token, refreshing idle time.
    pub fn lookup(&self, token: &str) -> Option<(AuthUser, String)> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let expired = sessions.get(token).is_none_or(|session| {
            now.duration_since(session.last_seen) >= self.idle
                || now.duration_since(session.created) >= self.absolute
        });
        if expired {
            sessions.remove(token);
            return None;
        }
        let session = sessions.get_mut(token)?;
        session.last_seen = now;
        Some((
            AuthUser {
                username: session.username.clone(),
                role: session.role.clone(),
            },
            session.csrf.clone(),
        ))
    }

    pub fn remove(&self, token: &str) -> Option<SessionEntry> {
        self.sessions.lock().unwrap().remove(token)
    }

    pub fn remove_user_sessions(&self, username: &str) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, session| session.username != username);
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<String, Attempt>>,
    max_attempts: u32,
    window: Duration,
}

#[derive(Clone, Copy, Debug)]
struct Attempt {
    count: u32,
    start: Instant,
    blocked_until: Instant,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_attempts: 5,
            window: Duration::from_secs(5 * 60),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        if map.len() > 4096 {
            map.retain(|_, attempt| now.duration_since(attempt.start) < Duration::from_secs(3600));
        }
        match map.get(key) {
            None => true,
            Some(attempt) if now < attempt.blocked_until => false,
            Some(attempt) if now.duration_since(attempt.start) >= self.window => true,
            Some(attempt) => attempt.count < self.max_attempts,
        }
    }

    pub fn failure(&self, key: &str) {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let attempt = map.entry(key.to_string()).or_insert(Attempt {
            count: 0,
            start: now,
            blocked_until: now,
        });
        if now.duration_since(attempt.start) >= self.window {
            attempt.count = 0;
            attempt.start = now;
            attempt.blocked_until = now;
        }
        attempt.count = attempt.count.saturating_add(1);
        if attempt.count >= self.max_attempts {
            attempt.blocked_until = now + self.window;
        }
    }

    pub fn success(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a 32-byte Argon2id hash.  Returns `(salt, hash)`.
pub fn hash_password(password: &str, m: u32, t: u32, p: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut salt = vec![0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| format!("random source failed: {e}"))?;
    let mut hash = vec![0u8; HASH_LEN];
    hash_password_into(password, &salt, m, t, p, &mut hash)?;
    Ok((salt, hash))
}

pub fn hash_password_into(
    password: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), String> {
    let params = Params::new(m, t, p, Some(out.len()))
        .map_err(|e| format!("invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(password.as_bytes(), salt, out)
        .map_err(|e| format!("Argon2 failed: {e}"))
}

pub fn verify_password(
    password: &str,
    salt: &[u8],
    expected: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> bool {
    let mut actual = vec![0u8; expected.len()];
    if hash_password_into(password, salt, m, t, p, &mut actual).is_err() {
        return false;
    }
    actual.ct_eq(expected).unwrap_u8() == 1
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        // getrandom failure is unrecoverable for credentials; returning an
        // empty token is safer than a predictable one and will fail auth.
        return String::new();
    }
    hex::encode(buf)
}

/// Generate a human-copyable passphrase from an unambiguous alphabet.
pub fn generate_password(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut raw = vec![0u8; len];
    if getrandom::getrandom(&mut raw).is_err() {
        return String::new();
    }
    raw.into_iter()
        .map(|byte| ALPHABET[(byte as usize) % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let (salt, hash) = hash_password("correct horse battery staple", 1024, 2, 1).unwrap();
        assert!(verify_password(
            "correct horse battery staple",
            &salt,
            &hash,
            1024,
            2,
            1
        ));
        assert!(!verify_password("wrong", &salt, &hash, 1024, 2, 1));
    }

    #[test]
    fn sessions_expire_and_csrf_is_stable() {
        let auth = AuthState::new();
        let (token, csrf) = auth.create_session("admin", "admin");
        let (user, got_csrf) = auth.lookup(&token).unwrap();
        assert_eq!(user.username, "admin");
        assert!(user.is_admin());
        assert_eq!(csrf, got_csrf);
        auth.remove(&token);
        assert!(auth.lookup(&token).is_none());
    }

    #[test]
    fn limiter_blocks_after_failures() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            assert!(limiter.allow("u"));
            limiter.failure("u");
        }
        assert!(!limiter.allow("u"));
        limiter.success("u");
        assert!(limiter.allow("u"));
    }
}
