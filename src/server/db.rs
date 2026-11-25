//! The hub's SQLite database: machines and pre-auth keys.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::now_unix;

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub name: String,
    pub ip: Ipv4Addr,
    pub key: String,
    pub hostname: String,
    pub created: i64,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AuthKeyRow {
    pub id: i64,
    pub prefix: String,
    pub reusable: bool,
    pub expires: Option<i64>,
    pub used: i64,
    pub revoked: bool,
    pub created: i64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS nodes(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL UNIQUE,
    key TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS authkeys(
    id INTEGER PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    reusable INTEGER NOT NULL,
    expires INTEGER,
    used INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
";

fn hash_key(k: &str) -> String {
    hex::encode(Sha256::digest(k.trim().as_bytes()))
}

/// Turn a hostname into a DNS label: lower-case `a-z0-9-`, at most 63 chars.
pub fn sanitise_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out: String = out.trim_matches('-').chars().take(63).collect();
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() { "node".into() } else { out }
}

fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRow> {
    let ip: String = r.get(2)?;
    Ok(NodeRow {
        id: r.get(0)?,
        name: r.get(1)?,
        ip: ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
        key: r.get(3)?,
        hostname: r.get(4)?,
        created: r.get(5)?,
        last_seen: r.get(6)?,
    })
}

const NODE_COLS: &str = "id, name, ip, key, hostname, created, last_seen";

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        Db { conn }
    }

    /// Changes whenever another connection commits a write.
    pub fn data_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
    }

    pub fn nodes(&self) -> Result<Vec<NodeRow>> {
        all_nodes(&self.conn)
    }

    pub fn node_by_key(&self, key: &str) -> Result<Option<NodeRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {NODE_COLS} FROM nodes WHERE key = ?1"),
                [key],
                row_to_node,
            )
            .optional()?)
    }

    pub fn node_by_name(&self, name: &str) -> Result<Option<NodeRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {NODE_COLS} FROM nodes WHERE name = ?1"),
                [name],
                row_to_node,
            )
            .optional()?)
    }

    /// Register a machine, consuming `auth_key`.
    pub fn register(&mut self, key: &str, hostname: &str, auth_key: &str) -> Result<NodeRow> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = now_unix();
        let ak: Option<(i64, bool, Option<i64>, i64, bool)> = tx
            .query_row(
                "SELECT id, reusable, expires, used, revoked FROM authkeys WHERE hash = ?1",
                [hash_key(auth_key)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((ak_id, reusable, expires, used, revoked)) = ak else {
            bail!("invalid auth key");
        };
        if revoked {
            bail!("auth key has been revoked");
        }
        if expires.is_some_and(|e| e <= now) {
            bail!("auth key has expired");
        }
        if !reusable && used > 0 {
            bail!("auth key has already been used");
        }
        tx.execute("UPDATE authkeys SET used = used + 1 WHERE id = ?1", [ak_id])?;
        let name = unique_name(&tx, hostname)?;
        let ip = next_ip(&tx)?;
        tx.execute(
            "INSERT INTO nodes(name, ip, key, hostname, created, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![name, ip.to_string(), key, hostname, now],
        )?;
        tx.commit()?;
        self.node_by_key(key)?.context("node vanished after insert")
    }

    pub fn touch(&self, key: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE nodes SET last_seen = ?1 WHERE key = ?2",
            params![now_unix(), key],
        )?;
        Ok(())
    }

    pub fn remove_node(&self, name: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM nodes WHERE name = ?1", [name])? > 0)
    }

    pub fn rename_node(&self, old: &str, new: &str) -> Result<String> {
        let new = sanitise_name(new);
        if self.node_by_name(&new)?.is_some() {
            bail!("a machine named {new} already exists");
        }
        if self
            .conn
            .execute("UPDATE nodes SET name = ?1 WHERE name = ?2", [&new, old])?
            == 0
        {
            bail!("no machine named {old}");
        }
        Ok(new)
    }

    /// Create a pre-auth key. Returns the secret, shown once.
    pub fn create_authkey(&self, reusable: bool, expires: Option<i64>) -> Result<String> {
        let secret = format!("tckey-{}", hex::encode(rand::random::<[u8; 24]>()));
        let prefix: String = secret.chars().take(14).collect();
        self.conn.execute(
            "INSERT INTO authkeys(hash, prefix, reusable, expires, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash_key(&secret), prefix, reusable, expires, now_unix()],
        )?;
        Ok(secret)
    }

    pub fn authkeys(&self) -> Result<Vec<AuthKeyRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id, prefix, reusable, expires, used, revoked, created FROM authkeys ORDER BY id")?;
        let rows = st
            .query_map([], |r| {
                Ok(AuthKeyRow {
                    id: r.get(0)?,
                    prefix: r.get(1)?,
                    reusable: r.get(2)?,
                    expires: r.get(3)?,
                    used: r.get(4)?,
                    revoked: r.get(5)?,
                    created: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn revoke_authkey(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("UPDATE authkeys SET revoked = 1 WHERE id = ?1", [id])?
            > 0)
    }
}

fn all_nodes(conn: &Connection) -> Result<Vec<NodeRow>> {
    let mut st = conn.prepare(&format!("SELECT {NODE_COLS} FROM nodes ORDER BY name"))?;
    let rows = st.query_map([], row_to_node)?.collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn unique_name(conn: &Connection, base: &str) -> Result<String> {
    let base = sanitise_name(base);
    let taken: HashSet<String> = all_nodes(conn)?.into_iter().map(|n| n.name).collect();
    if !taken.contains(&base) {
        return Ok(base);
    }
    for i in 2.. {
        let suffix = format!("-{i}");
        let stem: String = base.chars().take(63 - suffix.len()).collect();
        let cand = format!("{stem}{suffix}");
        if !taken.contains(&cand) {
            return Ok(cand);
        }
    }
    unreachable!()
}

/// Lowest free address in 100.64.0.0/10, skipping .0, .255 and the DNS address.
fn next_ip(conn: &Connection) -> Result<Ipv4Addr> {
    let used: HashSet<Ipv4Addr> = all_nodes(conn)?.into_iter().map(|n| n.ip).collect();
    let start = u32::from(Ipv4Addr::new(100, 64, 0, 1));
    let end = u32::from(Ipv4Addr::new(100, 127, 255, 254));
    for n in start..=end {
        let ip = Ipv4Addr::from(n);
        let last = ip.octets()[3];
        if last == 0 || last == 255 || ip == crate::MAGIC_DNS_IP || used.contains(&ip) {
            continue;
        }
        return Ok(ip);
    }
    bail!("address space exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitised() {
        assert_eq!(sanitise_name("Richard's MacBook Pro"), "richard-s-macbook-pro");
        assert_eq!(sanitise_name("--"), "node");
    }

    #[test]
    fn register_allocates_unique_names_and_ips() {
        let mut db = Db::memory();
        let k = db.create_authkey(true, None).unwrap();
        let a = db.register("ssh-ed25519 A", "box", &k).unwrap();
        let b = db.register("ssh-ed25519 B", "box", &k).unwrap();
        assert_eq!((a.name.as_str(), a.ip), ("box", Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!((b.name.as_str(), b.ip), ("box-2", Ipv4Addr::new(100, 64, 0, 2)));
    }

    #[test]
    fn single_use_and_revoked_keys() {
        let mut db = Db::memory();
        let k = db.create_authkey(false, None).unwrap();
        db.register("ssh-ed25519 A", "a", &k).unwrap();
        assert!(db.register("ssh-ed25519 B", "b", &k).is_err());
        let k2 = db.create_authkey(true, None).unwrap();
        let id = db.authkeys().unwrap().last().unwrap().id;
        db.revoke_authkey(id).unwrap();
        assert!(db.register("ssh-ed25519 C", "c", &k2).is_err());
        let k3 = db.create_authkey(true, Some(now_unix() - 1)).unwrap();
        assert!(db.register("ssh-ed25519 D", "d", &k3).is_err());
        assert!(db.register("ssh-ed25519 E", "e", "tckey-bogus").is_err());
    }
}
