//! SQLite persistence for admin accounts, sessions, traffic and audit data.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{id_hex, now_unix, Counters, PeerId, SessionEnd, SessionStart, TrafficTotals};

#[derive(Clone, Debug)]
pub struct AdminRecord {
    pub username: String,
    pub role: String,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Clone, Debug, Default)]
pub struct PeerMeta {
    pub name: String,
    pub notes: Option<String>,
    pub quota_bytes_month: Option<u64>,
    pub last_seen_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub session_id: u64,
    pub peer_id: String,
    pub addr: String,
    pub proto: String,
    pub mode: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub end_reason: Option<String>,
    pub counters: Counters,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TrafficPoint {
    pub ts: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub payload_in: u64,
    pub payload_out: u64,
}

#[derive(Clone, Debug)]
pub struct AuditRow {
    pub id: i64,
    pub ts: i64,
    pub user: String,
    pub ip: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub result: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {e}", parent.display()))?;
            }
        }
        let existed = path.exists();
        let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        if !existed {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("open memory db: {e}"))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, String> {
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| format!("sqlite busy_timeout: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| format!("sqlite pragmas: {e}"))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        // Open sessions are reconciled against the server's control plane by
        // the admin daemon; closing them here would wrongly end live sessions
        // when only the admin process restarts.
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             INSERT INTO schema_version(version)
               SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
             CREATE TABLE IF NOT EXISTS peer_meta (
               id BLOB PRIMARY KEY,
               name TEXT NOT NULL,
               notes TEXT,
               quota_bytes_month INTEGER,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               last_seen_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS session (
               session_id INTEGER PRIMARY KEY,
               peer_id BLOB NOT NULL,
               addr TEXT NOT NULL,
               proto TEXT NOT NULL,
               mode TEXT NOT NULL,
               started_at INTEGER NOT NULL,
               ended_at INTEGER,
               end_reason TEXT,
               bytes_in INTEGER NOT NULL DEFAULT 0,
               bytes_out INTEGER NOT NULL DEFAULT 0,
               payload_in INTEGER NOT NULL DEFAULT 0,
               payload_out INTEGER NOT NULL DEFAULT 0,
               frames_in INTEGER NOT NULL DEFAULT 0,
               frames_out INTEGER NOT NULL DEFAULT 0,
               unauth INTEGER NOT NULL DEFAULT 0,
               dup INTEGER NOT NULL DEFAULT 0,
               heartbeat_sent INTEGER NOT NULL DEFAULT 0,
               heartbeat_recv INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS session_peer_started
               ON session(peer_id, started_at);
             CREATE TABLE IF NOT EXISTS sample_1m (
               peer_id BLOB NOT NULL,
               ts INTEGER NOT NULL,
               bytes_in INTEGER NOT NULL,
               bytes_out INTEGER NOT NULL,
               payload_in INTEGER NOT NULL,
               payload_out INTEGER NOT NULL,
               PRIMARY KEY (peer_id, ts)
             );
             CREATE TABLE IF NOT EXISTS sample_1h (
               peer_id BLOB NOT NULL,
               ts INTEGER NOT NULL,
               bytes_in INTEGER NOT NULL,
               bytes_out INTEGER NOT NULL,
               payload_in INTEGER NOT NULL,
               payload_out INTEGER NOT NULL,
               PRIMARY KEY (peer_id, ts)
             );
             CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts INTEGER NOT NULL,
               user TEXT NOT NULL,
               ip TEXT,
               action TEXT NOT NULL,
               target TEXT,
               detail TEXT,
               result TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS admin_user (
               username TEXT PRIMARY KEY,
               role TEXT NOT NULL,
               pw_salt BLOB NOT NULL,
               pw_hash BLOB NOT NULL,
               pw_m INTEGER NOT NULL,
               pw_t INTEGER NOT NULL,
               pw_p INTEGER NOT NULL,
               totp_secret BLOB,
               created_at INTEGER NOT NULL,
               disabled INTEGER NOT NULL DEFAULT 0
             );",
        )
        .map_err(|e| format!("sqlite migrate: {e}"))?;
        Ok(())
    }

    // ---- admin accounts -------------------------------------------------

    pub fn admin_count(&self) -> Result<u64, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM admin_user", [], |row| {
            row.get::<_, i64>(0).map(|count| count as u64)
        })
        .map_err(|e| e.to_string())
    }

    pub fn get_admin(&self, username: &str) -> Result<Option<AdminRecord>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT username, role, pw_salt, pw_hash, pw_m, pw_t, pw_p
             FROM admin_user WHERE username = ?1 AND disabled = 0",
            params![username],
            |row| {
                Ok(AdminRecord {
                    username: row.get(0)?,
                    role: row.get(1)?,
                    salt: row.get(2)?,
                    hash: row.get(3)?,
                    m: row.get(4)?,
                    t: row.get(5)?,
                    p: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_admin(
        &self,
        username: &str,
        role: &str,
        salt: &[u8],
        hash: &[u8],
        m: u32,
        t: u32,
        p: u32,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO admin_user
               (username, role, pw_salt, pw_hash, pw_m, pw_t, pw_p, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(username) DO UPDATE SET
               role = excluded.role, pw_salt = excluded.pw_salt,
               pw_hash = excluded.pw_hash, pw_m = excluded.pw_m,
               pw_t = excluded.pw_t, pw_p = excluded.pw_p, disabled = 0",
            params![username, role, salt, hash, m, t, p, now_unix()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_admins(&self) -> Result<Vec<(String, String)>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT username, role FROM admin_user ORDER BY username")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    // ---- peer metadata --------------------------------------------------

    pub fn upsert_peer_meta(
        &self,
        id: &PeerId,
        name: &str,
        notes: Option<&str>,
        quota: Option<u64>,
    ) -> Result<(), String> {
        let now = now_unix();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO peer_meta
               (id, name, notes, quota_bytes_month, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               notes = excluded.notes,
               quota_bytes_month = excluded.quota_bytes_month,
               updated_at = excluded.updated_at",
            params![&id[..], name, notes, quota.map(|quota| quota as i64), now],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn set_peer_meta(
        &self,
        id: &PeerId,
        notes: Option<&str>,
        quota: Option<u64>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE peer_meta SET notes = ?2, quota_bytes_month = ?3, updated_at = ?4
             WHERE id = ?1",
            params![&id[..], notes, quota.map(|quota| quota as i64), now_unix()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn all_peer_meta(&self) -> Result<HashMap<PeerId, PeerMeta>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, notes, quota_bytes_month, last_seen_at
                 FROM peer_meta",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let raw: Vec<u8> = row.get(0)?;
                let mut id = [0u8; 16];
                if raw.len() == 16 {
                    id.copy_from_slice(&raw);
                }
                Ok((
                    id,
                    PeerMeta {
                        name: row.get(1)?,
                        notes: row.get(2)?,
                        quota_bytes_month: row.get::<_, Option<i64>>(3)?.map(|quota| quota as u64),
                        last_seen_at: row.get(4)?,
                    },
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = HashMap::new();
        for row in rows {
            let (id, meta) = row.map_err(|e| e.to_string())?;
            out.insert(id, meta);
        }
        Ok(out)
    }

    // ---- sessions and traffic ------------------------------------------

    pub fn start_session(&self, start: &SessionStart) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO session
               (session_id, peer_id, addr, proto, mode, started_at, bytes_in, bytes_out,
                payload_in, payload_out, frames_in, frames_out, unauth, dup,
                heartbeat_sent, heartbeat_recv)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                start.session_id as i64,
                &start.peer_id[..],
                start.addr,
                start.proto,
                start.mode,
                start.started_at,
                start.counters.bytes_in as i64,
                start.counters.bytes_out as i64,
                start.counters.payload_in as i64,
                start.counters.payload_out as i64,
                start.counters.frames_in as i64,
                start.counters.frames_out as i64,
                start.counters.unauth as i64,
                start.counters.dup as i64,
                start.counters.heartbeat_sent as i64,
                start.counters.heartbeat_recv as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn finish_session(&self, end: &SessionEnd, only_if_open: bool) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let where_open = if only_if_open {
            " AND ended_at IS NULL"
        } else {
            ""
        };
        let updated = conn
            .execute(
                &format!(
                    "UPDATE session SET ended_at = ?2, end_reason = ?3,
                       bytes_in = ?4, bytes_out = ?5, payload_in = ?6, payload_out = ?7,
                       frames_in = ?8, frames_out = ?9, unauth = ?10, dup = ?11,
                       heartbeat_sent = ?12, heartbeat_recv = ?13
                     WHERE session_id = ?1{where_open}"
                ),
                params![
                    end.session_id as i64,
                    end.ended_at,
                    end.reason,
                    end.counters.bytes_in as i64,
                    end.counters.bytes_out as i64,
                    end.counters.payload_in as i64,
                    end.counters.payload_out as i64,
                    end.counters.frames_in as i64,
                    end.counters.frames_out as i64,
                    end.counters.unauth as i64,
                    end.counters.dup as i64,
                    end.counters.heartbeat_sent as i64,
                    end.counters.heartbeat_recv as i64,
                ],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            if only_if_open {
                let exists = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM session WHERE session_id = ?1)",
                        params![end.session_id as i64],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|e| e.to_string())?;
                if exists != 0 {
                    return Ok(());
                }
            }
            conn.execute(
                "INSERT OR IGNORE INTO session
                   (session_id, peer_id, addr, proto, mode, started_at, ended_at, end_reason,
                    bytes_in, bytes_out, payload_in, payload_out, frames_in, frames_out,
                    unauth, dup, heartbeat_sent, heartbeat_recv)
                 VALUES (?1, ?2, '', '', '', ?3, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    end.session_id as i64,
                    &end.peer_id[..],
                    end.ended_at,
                    end.reason,
                    end.counters.bytes_in as i64,
                    end.counters.bytes_out as i64,
                    end.counters.payload_in as i64,
                    end.counters.payload_out as i64,
                    end.counters.frames_in as i64,
                    end.counters.frames_out as i64,
                    end.counters.unauth as i64,
                    end.counters.dup as i64,
                    end.counters.heartbeat_sent as i64,
                    end.counters.heartbeat_recv as i64,
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn open_session_ids(&self) -> Result<Vec<u64>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT session_id FROM session WHERE ended_at IS NULL")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(|e| e.to_string())?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| e.to_string())? as u64);
        }
        Ok(ids)
    }

    pub fn close_session(
        &self,
        session_id: u64,
        reason: &str,
        ended_at: i64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session SET ended_at = ?2, end_reason = ?3
             WHERE session_id = ?1 AND ended_at IS NULL",
            params![session_id as i64, ended_at, reason],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn close_orphan_sessions(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session SET ended_at = ?1, end_reason = 'server_restart'
             WHERE ended_at IS NULL",
            params![now_unix()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_sessions(&self, peer_id: &PeerId, limit: usize) -> Result<Vec<SessionRow>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT session_id, peer_id, addr, proto, mode, started_at, ended_at, end_reason,
                        bytes_in, bytes_out, payload_in, payload_out, frames_in, frames_out,
                        unauth, dup, heartbeat_sent, heartbeat_recv
                 FROM session WHERE peer_id = ?1
                 ORDER BY started_at DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![&peer_id[..], limit as i64], map_session_row)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn lifetime(&self, peer_id: &PeerId) -> Result<TrafficTotals, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                    COALESCE(SUM(payload_in),0), COALESCE(SUM(payload_out),0), COUNT(*)
             FROM session WHERE peer_id = ?1",
            params![&peer_id[..]],
            |row| {
                Ok(TrafficTotals {
                    bytes_in: row.get::<_, i64>(0)? as u64,
                    bytes_out: row.get::<_, i64>(1)? as u64,
                    payload_in: row.get::<_, i64>(2)? as u64,
                    payload_out: row.get::<_, i64>(3)? as u64,
                    sessions: row.get::<_, i64>(4)? as u64,
                })
            },
        )
        .map_err(|e| e.to_string())
    }

    pub fn lifetime_all(&self) -> Result<HashMap<PeerId, TrafficTotals>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT peer_id, COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                        COALESCE(SUM(payload_in),0), COALESCE(SUM(payload_out),0), COUNT(*)
                 FROM session GROUP BY peer_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let raw: Vec<u8> = row.get(0)?;
                let mut id = [0u8; 16];
                if raw.len() == 16 {
                    id.copy_from_slice(&raw);
                }
                Ok((
                    id,
                    TrafficTotals {
                        bytes_in: row.get::<_, i64>(1)? as u64,
                        bytes_out: row.get::<_, i64>(2)? as u64,
                        payload_in: row.get::<_, i64>(3)? as u64,
                        payload_out: row.get::<_, i64>(4)? as u64,
                        sessions: row.get::<_, i64>(5)? as u64,
                    },
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = HashMap::new();
        for row in rows {
            let (id, totals) = row.map_err(|e| e.to_string())?;
            out.insert(id, totals);
        }
        Ok(out)
    }

    pub fn add_samples(&self, rows: &[(PeerId, i64, i64, Counters)]) -> Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for (peer_id, minute, hour, counters) in rows {
            if counters.bytes_in == 0
                && counters.bytes_out == 0
                && counters.payload_in == 0
                && counters.payload_out == 0
            {
                continue;
            }
            tx.execute(
                "INSERT INTO sample_1m
                   (peer_id, ts, bytes_in, bytes_out, payload_in, payload_out)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(peer_id, ts) DO UPDATE SET
                   bytes_in = bytes_in + excluded.bytes_in,
                   bytes_out = bytes_out + excluded.bytes_out,
                   payload_in = payload_in + excluded.payload_in,
                   payload_out = payload_out + excluded.payload_out",
                params![
                    &peer_id[..],
                    minute,
                    counters.bytes_in as i64,
                    counters.bytes_out as i64,
                    counters.payload_in as i64,
                    counters.payload_out as i64
                ],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO sample_1h
                   (peer_id, ts, bytes_in, bytes_out, payload_in, payload_out)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(peer_id, ts) DO UPDATE SET
                   bytes_in = bytes_in + excluded.bytes_in,
                   bytes_out = bytes_out + excluded.bytes_out,
                   payload_in = payload_in + excluded.payload_in,
                   payload_out = payload_out + excluded.payload_out",
                params![
                    &peer_id[..],
                    hour,
                    counters.bytes_in as i64,
                    counters.bytes_out as i64,
                    counters.payload_in as i64,
                    counters.payload_out as i64
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist the latest cumulative counters for open sessions so a crash or
    /// restart loses at most one sampling interval.
    pub fn update_session_counters(&self, rows: &[(u64, Counters)]) -> Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for (session_id, counters) in rows {
            tx.execute(
                "UPDATE session SET
                   bytes_in = ?2, bytes_out = ?3, payload_in = ?4, payload_out = ?5,
                   frames_in = ?6, frames_out = ?7, unauth = ?8, dup = ?9,
                   heartbeat_sent = ?10, heartbeat_recv = ?11
                 WHERE session_id = ?1 AND ended_at IS NULL",
                params![
                    *session_id as i64,
                    counters.bytes_in as i64,
                    counters.bytes_out as i64,
                    counters.payload_in as i64,
                    counters.payload_out as i64,
                    counters.frames_in as i64,
                    counters.frames_out as i64,
                    counters.unauth as i64,
                    counters.dup as i64,
                    counters.heartbeat_sent as i64,
                    counters.heartbeat_recv as i64,
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn traffic_series(
        &self,
        peer_id: &PeerId,
        from: i64,
        to: i64,
        step: i64,
        hourly: bool,
    ) -> Result<Vec<TrafficPoint>, String> {
        let table = if hourly { "sample_1h" } else { "sample_1m" };
        let sql = format!(
            "SELECT (ts / ?2) * ?2 AS bucket,
                    COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0),
                    COALESCE(SUM(payload_in),0), COALESCE(SUM(payload_out),0)
             FROM {table}
             WHERE peer_id = ?1 AND ts >= ?3 AND ts < ?4
             GROUP BY bucket ORDER BY bucket"
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![&peer_id[..], step, from, to], |row| {
                Ok(TrafficPoint {
                    ts: row.get(0)?,
                    bytes_in: row.get::<_, i64>(1)? as u64,
                    bytes_out: row.get::<_, i64>(2)? as u64,
                    payload_in: row.get::<_, i64>(3)? as u64,
                    payload_out: row.get::<_, i64>(4)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn month_usage_all(&self, from: i64) -> Result<HashMap<PeerId, u64>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT peer_id, COALESCE(SUM(payload_in + payload_out),0)
                 FROM sample_1h WHERE ts >= ?1 GROUP BY peer_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![from], |row| {
                let raw: Vec<u8> = row.get(0)?;
                let mut id = [0u8; 16];
                if raw.len() == 16 {
                    id.copy_from_slice(&raw);
                }
                Ok((id, row.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| e.to_string())?;
        let mut out = HashMap::new();
        for row in rows {
            let (id, usage) = row.map_err(|e| e.to_string())?;
            out.insert(id, usage);
        }
        Ok(out)
    }

    pub fn total_usage_all(&self, from: i64) -> Result<(u64, u64), String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(payload_in),0), COALESCE(SUM(payload_out),0)
             FROM sample_1h WHERE ts >= ?1",
            params![from],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
        )
        .map_err(|e| e.to_string())
    }

    pub fn purge_peer(&self, peer_id: &PeerId) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for table in ["session", "sample_1m", "sample_1h", "peer_meta"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE {} = ?1",
                    if table == "peer_meta" {
                        "id"
                    } else {
                        "peer_id"
                    }
                ),
                params![&peer_id[..]],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), String> {
        let now = now_unix();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM sample_1m WHERE ts < ?1",
            params![now - 7 * 86_400],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM sample_1h WHERE ts < ?1",
            params![now - 90 * 86_400],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---- audit ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        user: &str,
        ip: &str,
        action: &str,
        target: &str,
        detail: &str,
        result: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit (ts, user, ip, action, target, detail, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![now_unix(), user, ip, action, target, detail, result],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_audit(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<AuditRow>, String> {
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        if let Some(before) = before_id {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ts, user, ip, action, target, detail, result
                     FROM audit WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![before, limit as i64], map_audit_row)
                .map_err(|e| e.to_string())?;
            for row in rows {
                out.push(row.map_err(|e| e.to_string())?);
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ts, user, ip, action, target, detail, result
                     FROM audit ORDER BY id DESC LIMIT ?1",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![limit as i64], map_audit_row)
                .map_err(|e| e.to_string())?;
            for row in rows {
                out.push(row.map_err(|e| e.to_string())?);
            }
        }
        Ok(out)
    }

    pub fn admin_summary(&self) -> Result<Vec<(String, String)>, String> {
        self.list_admins()
    }

    pub fn session_meta(&self, session_id: u64) -> Result<Option<SessionRow>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT session_id, peer_id, addr, proto, mode, started_at, ended_at, end_reason,
                    bytes_in, bytes_out, payload_in, payload_out, frames_in, frames_out,
                    unauth, dup, heartbeat_sent, heartbeat_recv
             FROM session WHERE session_id = ?1",
            params![session_id as i64],
            map_session_row,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn peer_label(&self, id: &PeerId) -> Result<Option<PeerMeta>, String> {
        let all = self.all_peer_meta()?;
        Ok(all.get(id).cloned())
    }

    pub fn id_label(id: &PeerId) -> String {
        id_hex(id)
    }
}

fn map_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    let raw: Vec<u8> = row.get(1)?;
    let mut id = [0u8; 16];
    if raw.len() == 16 {
        id.copy_from_slice(&raw);
    }
    Ok(SessionRow {
        session_id: row.get::<_, i64>(0)? as u64,
        peer_id: id_hex(&id),
        addr: row.get(2)?,
        proto: row.get(3)?,
        mode: row.get(4)?,
        started_at: row.get(5)?,
        ended_at: row.get(6)?,
        end_reason: row.get(7)?,
        counters: Counters {
            bytes_in: row.get::<_, i64>(8)? as u64,
            bytes_out: row.get::<_, i64>(9)? as u64,
            payload_in: row.get::<_, i64>(10)? as u64,
            payload_out: row.get::<_, i64>(11)? as u64,
            frames_in: row.get::<_, i64>(12)? as u64,
            frames_out: row.get::<_, i64>(13)? as u64,
            unauth: row.get::<_, i64>(14)? as u64,
            dup: row.get::<_, i64>(15)? as u64,
            heartbeat_sent: row.get::<_, i64>(16)? as u64,
            heartbeat_recv: row.get::<_, i64>(17)? as u64,
        },
    })
}

fn map_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        id: row.get(0)?,
        ts: row.get(1)?,
        user: row.get(2)?,
        ip: row.get(3)?,
        action: row.get(4)?,
        target: row.get(5)?,
        detail: row.get(6)?,
        result: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SessionStart;

    fn start(id: u8) -> SessionStart {
        SessionStart {
            session_id: 1,
            peer_id: [id; 16],
            name: "alice".into(),
            addr: "1.2.3.4:5".into(),
            proto: "udp".into(),
            mode: "noise".into(),
            started_at: 1_000,
            counters: Counters::default(),
        }
    }

    #[test]
    fn session_and_sample_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let s = start(7);
        store.start_session(&s).unwrap();
        store
            .add_samples(&[(
                s.peer_id,
                60,
                0,
                Counters {
                    bytes_in: 100,
                    payload_in: 80,
                    ..Counters::default()
                },
            )])
            .unwrap();
        store
            .update_session_counters(&[(
                1,
                Counters {
                    bytes_in: 250,
                    payload_in: 200,
                    ..Counters::default()
                },
            )])
            .unwrap();
        assert_eq!(store.lifetime(&s.peer_id).unwrap().bytes_in, 250);
        store
            .finish_session(
                &SessionEnd {
                    session_id: 1,
                    peer_id: s.peer_id,
                    ended_at: 2_000,
                    reason: "timeout".into(),
                    counters: Counters {
                        bytes_in: 500,
                        payload_in: 400,
                        ..Counters::default()
                    },
                },
                false,
            )
            .unwrap();
        let lifetime = store.lifetime(&s.peer_id).unwrap();
        assert_eq!(lifetime.bytes_in, 500);
        assert_eq!(lifetime.sessions, 1);
        let points = store
            .traffic_series(&s.peer_id, 0, 10_000, 60, false)
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].bytes_in, 100);
        let usage = store.month_usage_all(0).unwrap();
        assert_eq!(usage.get(&s.peer_id), Some(&80));
    }

    #[test]
    fn admin_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.admin_count().unwrap(), 0);
        store
            .upsert_admin("admin", "admin", b"salt", b"hash", 1, 2, 3)
            .unwrap();
        let admin = store.get_admin("admin").unwrap().unwrap();
        assert_eq!(admin.role, "admin");
        assert_eq!(admin.m, 1);
    }
}
