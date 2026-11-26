//! The hub's SQLite database: accounts, machines, pre-auth keys, access
//! rules and shares.
//!
//! Schema versions (`PRAGMA user_version`):
//! * 0: machines and auth keys only (TailConnect-SSH 0.1).
//! * 1: accounts; machines, keys and rules belong to one; shares. A version
//!   0 database is migrated into an account named `default`.
//! * 2: the web portal: account passwords and roles, the `pending` status,
//!   invites, share links, settings (the admin token's hash).
//! * 3: exit nodes (`nodes.exit_node`).
//! * 4: key expiry, machine approval, ephemeral machines (`nodes.expires`,
//!   `nodes.approved`, `nodes.ephemeral`, `accounts.require_approval`,
//!   `authkeys.ephemeral`, `authkeys.preapproved`). Existing machines never
//!   expire.
//! * 5: per-account MagicDNS domains (`accounts.dns_domain`).
//! * 6: shared exit nodes (`shares.exit`): a share may also let the other
//!   account use the machine as its exit node. Existing shares don't.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::acl::{Access, Rule, valid_label};
use crate::now_unix;

pub struct Db {
    conn: Connection,
    /// How long new (and renewed) machines stay authorised; `None`: forever.
    key_expiry: Option<i64>,
    /// Addresses new machines get, inclusive (within 100.64.0.0/10).
    pool: (u32, u32),
}

/// The whole tailnet range.
const FULL_POOL: (u32, u32) = (0x6440_0000, 0x647f_ffff);

/// Parse an address pool such as `100.96.0.0/16`. It must lie within
/// 100.64.0.0/10, the range every machine routes into its tunnel.
pub fn parse_pool(s: &str) -> Result<(u32, u32)> {
    let (a, len) = s
        .trim()
        .split_once('/')
        .context("write the pool as ADDRESS/PREFIX, like 100.96.0.0/16")?;
    let a: Ipv4Addr = a.parse().context("bad pool address")?;
    let len: u32 = len.parse().context("bad pool prefix length")?;
    if !(10..=30).contains(&len) {
        bail!("pool prefix length must be 10 to 30");
    }
    let mask = u32::MAX << (32 - len);
    let start = u32::from(a) & mask;
    let end = start | !mask;
    if start < FULL_POOL.0 || end > FULL_POOL.1 {
        bail!("the pool must lie within 100.64.0.0/10");
    }
    Ok((start, end))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Active,
    /// Signed up in the portal, waiting for an operator's approval.
    Pending,
    Suspended,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Pending => "pending",
            Status::Suspended => "suspended",
        }
    }

    fn parse(s: &str) -> Self {
        // Anything unexpected counts as suspended: fail closed.
        match s {
            "active" => Status::Active,
            "pending" => Status::Pending,
            _ => Status::Suspended,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Tenant,
    /// Manages the server: every account, machine, key, rule and share.
    Operator,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Tenant => "tenant",
            Role::Operator => "operator",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "tenant" => Ok(Role::Tenant),
            "operator" => Ok(Role::Operator),
            _ => bail!("role must be operator or tenant"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: i64,
    pub name: String,
    pub status: Status,
    pub created: i64,
    pub role: Role,
    pub has_password: bool,
    /// When the password, role or status last changed: sessions from before
    /// then are no longer valid.
    pub changed: i64,
    /// New machines wait for approval.
    pub require_approval: bool,
    /// The account's own MagicDNS domain (`None`: `ACCOUNT.<hub domain>`).
    pub dns_domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: i64,
    pub prefix: String,
    pub expires: i64,
    pub used_by: Option<String>,
    pub revoked: bool,
    pub created: i64,
}

#[derive(Debug, Clone)]
pub struct ShareLinkRow {
    pub id: i64,
    pub prefix: String,
    pub node_id: i64,
    pub node: String,
    pub owner_id: i64,
    pub owner: String,
    pub ports: String,
    pub expires: i64,
    pub used_by: Option<String>,
    pub revoked: bool,
    pub created: i64,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub account_id: i64,
    pub account: String,
    pub name: String,
    pub ip: Ipv4Addr,
    pub key: String,
    pub hostname: String,
    pub tags: Vec<String>,
    /// May route internet traffic for its account's machines.
    pub exit_node: bool,
    pub created: i64,
    pub last_seen: Option<i64>,
    /// When the machine's authorisation ends (`None`: never).
    pub expires: Option<i64>,
    /// `false`: waiting for its account's approval.
    pub approved: bool,
    /// Removed automatically after being offline for a while.
    pub ephemeral: bool,
}

impl NodeRow {
    pub fn expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|e| e <= now)
    }
}

#[derive(Debug, Clone)]
pub struct AuthKeyRow {
    pub id: i64,
    pub account: String,
    pub prefix: String,
    pub reusable: bool,
    pub expires: Option<i64>,
    pub used: i64,
    pub revoked: bool,
    pub created: i64,
    pub ephemeral: bool,
    pub preapproved: bool,
}

#[derive(Debug, Clone)]
pub struct RuleRow {
    pub id: i64,
    pub account_id: i64,
    pub account: String,
    pub src: String,
    pub dst: String,
    pub ports: String,
}

#[derive(Debug, Clone)]
pub struct ShareRow {
    pub id: i64,
    pub node_id: i64,
    pub node: String,
    /// The shared machine's account.
    pub owner_id: i64,
    pub owner: String,
    /// The account it's shared with.
    pub account_id: i64,
    pub account: String,
    pub ports: String,
    pub accepted: bool,
    pub created: i64,
    /// The other account may also use the machine as its exit node (if it
    /// is one, and the share covers every port).
    pub exit: bool,
}

const SCHEMA_V1: &str = "
CREATE TABLE accounts(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created INTEGER NOT NULL
);
CREATE TABLE nodes(
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    key TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,
    last_seen INTEGER,
    UNIQUE(account_id, name)
);
CREATE TABLE authkeys(
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    reusable INTEGER NOT NULL,
    expires INTEGER,
    used INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
CREATE TABLE rules(
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    ports TEXT NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE shares(
    id INTEGER PRIMARY KEY,
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    ports TEXT NOT NULL DEFAULT '*',
    accepted INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL,
    UNIQUE(node_id, account_id)
);
";

const SCHEMA_V2_UPGRADE: &str = "
ALTER TABLE accounts ADD COLUMN password_hash TEXT;
ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'tenant';
ALTER TABLE accounts ADD COLUMN changed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE invites(
    id INTEGER PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    expires INTEGER NOT NULL,
    used_by INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
CREATE TABLE share_links(
    id INTEGER PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    ports TEXT NOT NULL,
    expires INTEGER NOT NULL,
    used_by INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
CREATE TABLE settings(
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
";

const SCHEMA_VERSION: i64 = 6;

/// How long a machine's authorisation lasts by default: 180 days.
pub const DEFAULT_KEY_EXPIRY: i64 = 180 * 86400;

/// Name of the account that machines from a version 0 database move into.
pub const DEFAULT_ACCOUNT: &str = "default";

fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version > SCHEMA_VERSION {
        bail!("database schema version {version} is newer than this tc-control understands ({SCHEMA_VERSION})");
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    if version == 0 {
        let has_nodes: bool = tx
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'nodes'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)?;
        if has_nodes {
            // Version 0: move everything into the default account.
            tx.execute_batch(
                "ALTER TABLE nodes RENAME TO nodes_v0;
                 ALTER TABLE authkeys RENAME TO authkeys_v0;",
            )?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.execute(
                "INSERT INTO accounts(name, created) VALUES (?1, ?2)",
                params![DEFAULT_ACCOUNT, now_unix()],
            )?;
            let acct = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO nodes(id, account_id, name, ip, key, hostname, created, last_seen)
                 SELECT id, ?1, name, ip, key, hostname, created, last_seen FROM nodes_v0",
                [acct],
            )?;
            tx.execute(
                "INSERT INTO authkeys(id, account_id, hash, prefix, reusable, expires, used, revoked, created)
                 SELECT id, ?1, hash, prefix, reusable, expires, used, revoked, created FROM authkeys_v0",
                [acct],
            )?;
            tx.execute_batch("DROP TABLE nodes_v0; DROP TABLE authkeys_v0;")?;
        } else {
            tx.execute_batch(SCHEMA_V1)?;
        }
    }
    if version < 2 {
        tx.execute_batch(SCHEMA_V2_UPGRADE)?;
    }
    if version < 3 {
        tx.execute_batch("ALTER TABLE nodes ADD COLUMN exit_node INTEGER NOT NULL DEFAULT 0;")?;
    }
    if version < 4 {
        tx.execute_batch(
            "ALTER TABLE nodes ADD COLUMN expires INTEGER;
             ALTER TABLE nodes ADD COLUMN approved INTEGER NOT NULL DEFAULT 1;
             ALTER TABLE nodes ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE accounts ADD COLUMN require_approval INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE authkeys ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE authkeys ADD COLUMN preapproved INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if version < 5 {
        tx.execute_batch(
            "ALTER TABLE accounts ADD COLUMN dns_domain TEXT;
             CREATE UNIQUE INDEX accounts_dns_domain ON accounts(dns_domain) WHERE dns_domain IS NOT NULL;",
        )?;
    }
    if version < 6 {
        tx.execute_batch("ALTER TABLE shares ADD COLUMN exit INTEGER NOT NULL DEFAULT 0;")?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

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

fn split_tags(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

const NODE_SELECT: &str =
    "SELECT n.id, n.account_id, a.name, n.name, n.ip, n.key, n.hostname, n.tags, n.created, n.last_seen, n.exit_node,
            n.expires, n.approved, n.ephemeral
     FROM nodes n JOIN accounts a ON a.id = n.account_id";

fn row_to_node(r: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRow> {
    let ip: String = r.get(4)?;
    let tags: String = r.get(7)?;
    Ok(NodeRow {
        id: r.get(0)?,
        account_id: r.get(1)?,
        account: r.get(2)?,
        name: r.get(3)?,
        ip: ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
        key: r.get(5)?,
        hostname: r.get(6)?,
        tags: split_tags(&tags),
        created: r.get(8)?,
        last_seen: r.get(9)?,
        exit_node: r.get(10)?,
        expires: r.get(11)?,
        approved: r.get(12)?,
        ephemeral: r.get(13)?,
    })
}

const ACCOUNT_COLS: &str =
    "id, name, status, created, role, password_hash IS NOT NULL, changed, require_approval, dns_domain";

fn row_to_account(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    let status: String = r.get(2)?;
    let role: String = r.get(4)?;
    Ok(AccountRow {
        id: r.get(0)?,
        name: r.get(1)?,
        status: Status::parse(&status),
        created: r.get(3)?,
        // An unknown role grants nothing extra.
        role: Role::parse(&role).unwrap_or(Role::Tenant),
        has_password: r.get(5)?,
        changed: r.get(6)?,
        require_approval: r.get(7)?,
        dns_domain: r.get(8)?,
    })
}

const SHARE_SELECT: &str =
    "SELECT s.id, s.node_id, n.name, o.id, o.name, a.id, a.name, s.ports, s.accepted, s.created, s.exit
     FROM shares s JOIN nodes n ON n.id = s.node_id JOIN accounts o ON o.id = n.account_id
     JOIN accounts a ON a.id = s.account_id";

fn row_to_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<ShareRow> {
    Ok(ShareRow {
        id: r.get(0)?,
        node_id: r.get(1)?,
        node: r.get(2)?,
        owner_id: r.get(3)?,
        owner: r.get(4)?,
        account_id: r.get(5)?,
        account: r.get(6)?,
        ports: r.get(7)?,
        accepted: r.get(8)?,
        created: r.get(9)?,
        exit: r.get(10)?,
    })
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Db {
            conn,
            pool: FULL_POOL,
            key_expiry: Some(DEFAULT_KEY_EXPIRY),
        })
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();
        Db {
            conn,
            pool: FULL_POOL,
            key_expiry: Some(DEFAULT_KEY_EXPIRY),
        }
    }

    /// Hand out addresses from `pool` only (see [`parse_pool`]).
    pub fn set_pool(&mut self, pool: (u32, u32)) {
        self.pool = pool;
    }

    /// Changes whenever another connection commits a write.
    pub fn data_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
    }

    // ---- accounts ----

    pub fn accounts(&self) -> Result<Vec<AccountRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {ACCOUNT_COLS} FROM accounts ORDER BY name"))?;
        let rows = st.query_map([], row_to_account)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn account(&self, name: &str) -> Result<AccountRow> {
        self.conn
            .query_row(
                &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE name = ?1"),
                [name.trim()],
                row_to_account,
            )
            .optional()?
            .with_context(|| format!("no account named {name}"))
    }

    pub fn create_account(&self, name: &str) -> Result<AccountRow> {
        self.create_account_with(name, Status::Active, Role::Tenant, None)
    }

    /// Create an account. `password_hash` is a PHC string (see
    /// [`super::auth::hash_password`]); without one, the account can't sign
    /// in to the portal and is only for machines.
    pub fn create_account_with(
        &self,
        name: &str,
        status: Status,
        role: Role,
        password_hash: Option<&str>,
    ) -> Result<AccountRow> {
        let name = valid_account_name(name)?;
        if self.account(&name).is_ok() {
            bail!("an account named {name} already exists");
        }
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO accounts(name, created, status, role, password_hash, changed) VALUES (?1, ?2, ?3, ?4, ?5, ?2)",
            params![name, now, status.as_str(), role.as_str(), password_hash],
        )?;
        self.account(&name)
    }

    pub fn account_by_id(&self, id: i64) -> Result<AccountRow> {
        self.conn
            .query_row(
                &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?1"),
                [id],
                row_to_account,
            )
            .optional()?
            .with_context(|| format!("no account with id {id}"))
    }

    /// The stored password hash of an account, if it has one.
    pub fn password_hash(&self, name: &str) -> Result<Option<(AccountRow, String)>> {
        let Ok(a) = self.account(name) else { return Ok(None) };
        let h: Option<String> =
            self.conn
                .query_row("SELECT password_hash FROM accounts WHERE id = ?1", [a.id], |r| r.get(0))?;
        Ok(h.map(|h| (a, h)))
    }

    /// Set (or, with `None`, clear) an account's password. Ends its sessions.
    pub fn set_password(&self, name: &str, password_hash: Option<&str>) -> Result<()> {
        let a = self.account(name)?;
        self.conn.execute(
            "UPDATE accounts SET password_hash = ?1, changed = ?2 WHERE id = ?3",
            params![password_hash, now_unix(), a.id],
        )?;
        Ok(())
    }

    /// Change an account's role. Ends its sessions.
    pub fn set_role(&self, name: &str, role: Role) -> Result<()> {
        let a = self.account(name)?;
        self.conn.execute(
            "UPDATE accounts SET role = ?1, changed = ?2 WHERE id = ?3",
            params![role.as_str(), now_unix(), a.id],
        )?;
        Ok(())
    }

    /// Change an account's status. Ends its sessions.
    pub fn set_account_status(&self, name: &str, status: Status) -> Result<()> {
        let a = self.account(name)?;
        self.conn.execute(
            "UPDATE accounts SET status = ?1, changed = ?2 WHERE id = ?3",
            params![status.as_str(), now_unix(), a.id],
        )?;
        Ok(())
    }

    /// Delete an account with its machines, keys, rules and shares.
    pub fn delete_account(&mut self, name: &str) -> Result<()> {
        let a = self.account(name)?;
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM shares WHERE account_id = ?1 OR node_id IN (SELECT id FROM nodes WHERE account_id = ?1)",
            [a.id],
        )?;
        tx.execute(
            "DELETE FROM share_links WHERE node_id IN (SELECT id FROM nodes WHERE account_id = ?1)",
            [a.id],
        )?;
        for t in ["rules", "authkeys", "nodes"] {
            tx.execute(&format!("DELETE FROM {t} WHERE account_id = ?1"), [a.id])?;
        }
        tx.execute("DELETE FROM accounts WHERE id = ?1", [a.id])?;
        tx.commit()?;
        Ok(())
    }

    // ---- machines ----

    pub fn nodes(&self) -> Result<Vec<NodeRow>> {
        all_nodes(&self.conn)
    }

    pub fn node_by_key(&self, key: &str) -> Result<Option<NodeRow>> {
        Ok(self
            .conn
            .query_row(&format!("{NODE_SELECT} WHERE n.key = ?1"), [key], row_to_node)
            .optional()?)
    }

    pub fn node(&self, id: i64) -> Result<NodeRow> {
        self.conn
            .query_row(&format!("{NODE_SELECT} WHERE n.id = ?1"), [id], row_to_node)
            .optional()?
            .with_context(|| format!("no machine with id {id}"))
    }

    /// Find a machine by id or `name.account`.
    pub fn find_node(&self, s: &str) -> Result<NodeRow> {
        if let Ok(id) = s.parse::<i64>() {
            return self.node(id);
        }
        let (name, account) = s
            .split_once('.')
            .with_context(|| format!("name machines as ID or NAME.ACCOUNT (not {s:?})"))?;
        self.conn
            .query_row(
                &format!("{NODE_SELECT} WHERE n.name = ?1 AND a.name = ?2"),
                [name, account],
                row_to_node,
            )
            .optional()?
            .with_context(|| format!("no machine {name} in account {account}"))
    }

    /// Register a machine, consuming `auth_key`. The machine joins the key's
    /// account, approved unless the account requires approval (and the key
    /// isn't pre-approved), ephemeral if the key is.
    pub fn register(&mut self, key: &str, hostname: &str, auth_key: &str) -> Result<NodeRow> {
        let key_expiry = self.key_expiry;
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_unix();
        let k = use_authkey(&tx, auth_key, now)?;
        let require: bool = tx.query_row(
            "SELECT require_approval FROM accounts WHERE id = ?1",
            [k.account_id],
            |r| r.get(0),
        )?;
        let name = unique_name(&tx, k.account_id, hostname)?;
        let ip = next_ip(&tx, self.pool)?;
        tx.execute(
            "INSERT INTO nodes(account_id, name, ip, key, hostname, created, last_seen, expires, approved, ephemeral)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9)",
            params![
                k.account_id,
                name,
                ip.to_string(),
                key,
                hostname,
                now,
                key_expiry.map(|e| now + e),
                !require || k.preapproved,
                k.ephemeral
            ],
        )?;
        tx.commit()?;
        self.node_by_key(key)?.context("node vanished after insert")
    }

    /// Renew a registered machine's authorisation with an auth key of its
    /// own account (`tc up --authkey KEY`). A pre-approved key approves it too.
    pub fn reauthorize(&mut self, key: &str, auth_key: &str) -> Result<NodeRow> {
        let key_expiry = self.key_expiry;
        let n = self.node_by_key(key)?.context("machine not registered")?;
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_unix();
        let k = use_authkey(&tx, auth_key, now)?;
        if k.account_id != n.account_id {
            bail!("that auth key is for another account");
        }
        // A machine set to never expire stays that way.
        let expires = n.expires.map(|_| key_expiry.map(|e| now + e)).unwrap_or(None);
        tx.execute(
            "UPDATE nodes SET expires = ?1, approved = (approved OR ?2) WHERE id = ?3",
            params![expires, k.preapproved, n.id],
        )?;
        tx.commit()?;
        self.node_by_key(key)?.context("node vanished")
    }

    /// Set how long new and renewed machines stay authorised.
    pub fn set_key_expiry(&mut self, secs: Option<i64>) {
        self.key_expiry = secs;
    }

    pub fn key_expiry(&self) -> Option<i64> {
        self.key_expiry
    }

    /// The running hub's key lifetime (`--key-expiry`), as it recorded it;
    /// the default if it never ran. `None`: never.
    pub fn hub_key_expiry(&self) -> Option<i64> {
        match self.setting("key_expiry").ok().flatten().as_deref() {
            Some("never") => None,
            Some(s) => s.parse().ok().or(Some(DEFAULT_KEY_EXPIRY)),
            None => Some(DEFAULT_KEY_EXPIRY),
        }
    }

    /// Set when a machine's authorisation ends (`None`: never).
    pub fn set_node_expiry(&self, id: i64, expires: Option<i64>) -> Result<()> {
        if self
            .conn
            .execute("UPDATE nodes SET expires = ?1 WHERE id = ?2", params![expires, id])?
            == 0
        {
            bail!("no machine with id {id}");
        }
        Ok(())
    }

    /// Let a machine that waits for approval join.
    pub fn approve_node(&self, id: i64) -> Result<()> {
        if self.conn.execute("UPDATE nodes SET approved = 1 WHERE id = ?1", [id])? == 0 {
            bail!("no machine with id {id}");
        }
        Ok(())
    }

    /// Require (or stop requiring) approval for an account's new machines.
    /// Set an account's own MagicDNS domain (`None`: back to the default,
    /// `ACCOUNT.<hub domain>`). `hub_domain` is the hub's `--domain`; with
    /// `suffixes`, the domain must end in one of them (tenants); without,
    /// any domain will do (operators).
    pub fn set_dns_domain(
        &self,
        account: &str,
        domain: Option<&str>,
        hub_domain: &str,
        suffixes: Option<&[String]>,
    ) -> Result<Option<String>> {
        let a = self.account(account)?;
        let d = match domain.map(str::trim).filter(|d| !d.is_empty() && *d != "default") {
            None => None,
            Some(d) => Some(valid_dns_domain(d, hub_domain, suffixes)?),
        };
        let r = self
            .conn
            .execute("UPDATE accounts SET dns_domain = ?1 WHERE id = ?2", params![d, a.id]);
        match r {
            Ok(_) => Ok(d),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                bail!("another account already uses {}", d.unwrap_or_default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The hub's MagicDNS domain, as it recorded it when it last started.
    pub fn hub_domain(&self) -> String {
        self.setting("domain")
            .ok()
            .flatten()
            .unwrap_or_else(|| "tc.internal".into())
    }

    pub fn set_require_approval(&self, account: &str, on: bool) -> Result<()> {
        let a = self.account(account)?;
        self.conn.execute(
            "UPDATE accounts SET require_approval = ?1 WHERE id = ?2",
            params![on, a.id],
        )?;
        Ok(())
    }

    pub fn touch(&self, key: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE nodes SET last_seen = ?1 WHERE key = ?2",
            params![now_unix(), key],
        )?;
        Ok(())
    }

    /// Delete a machine and its shares.
    pub fn remove_node(&mut self, id: i64) -> Result<()> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM shares WHERE node_id = ?1", [id])?;
        tx.execute("DELETE FROM share_links WHERE node_id = ?1", [id])?;
        if tx.execute("DELETE FROM nodes WHERE id = ?1", [id])? == 0 {
            bail!("no machine with id {id}");
        }
        tx.commit()?;
        Ok(())
    }

    pub fn rename_node(&self, id: i64, new: &str) -> Result<String> {
        let n = self.node(id)?;
        let new = valid_label(new, "machine name")?;
        let taken: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM nodes WHERE account_id = ?1 AND name = ?2",
                params![n.account_id, new],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some_and(|t| t != id) {
            bail!("account {} already has a machine named {new}", n.account);
        }
        self.conn
            .execute("UPDATE nodes SET name = ?1 WHERE id = ?2", params![new, id])?;
        Ok(new)
    }

    /// Replace a machine's tags.
    /// Turn a machine's exit node role on or off.
    pub fn set_exit_node(&self, id: i64, on: bool) -> Result<()> {
        if self
            .conn
            .execute("UPDATE nodes SET exit_node = ?1 WHERE id = ?2", params![on, id])?
            == 0
        {
            bail!("no machine with id {id}");
        }
        Ok(())
    }

    pub fn set_tags(&self, id: i64, tags: &[String]) -> Result<Vec<String>> {
        let mut clean = Vec::new();
        for t in tags {
            let t = t.trim().trim_start_matches("tag:");
            if !t.is_empty() {
                clean.push(valid_label(t, "tag")?);
            }
        }
        clean.sort();
        clean.dedup();
        if self
            .conn
            .execute("UPDATE nodes SET tags = ?1 WHERE id = ?2", params![clean.join(","), id])?
            == 0
        {
            bail!("no machine with id {id}");
        }
        Ok(clean)
    }

    // ---- auth keys ----

    /// Create a pre-auth key for `account`. Returns the secret, shown once.
    pub fn create_authkey(&self, account: &str, reusable: bool, expires: Option<i64>) -> Result<String> {
        self.create_authkey_with(account, reusable, expires, false, false)
    }

    /// Create a pre-auth key. Ephemeral keys' machines are removed after
    /// being offline for a while; pre-approved keys' machines skip the
    /// account's machine approval. Returns the secret, shown once.
    pub fn create_authkey_with(
        &self,
        account: &str,
        reusable: bool,
        expires: Option<i64>,
        ephemeral: bool,
        preapproved: bool,
    ) -> Result<String> {
        let a = self.account(account)?;
        let secret = format!("tckey-{}", hex::encode(rand::random::<[u8; 24]>()));
        let prefix: String = secret.chars().take(14).collect();
        self.conn.execute(
            "INSERT INTO authkeys(account_id, hash, prefix, reusable, expires, created, ephemeral, preapproved)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                a.id,
                hash_key(&secret),
                prefix,
                reusable,
                expires,
                now_unix(),
                ephemeral,
                preapproved
            ],
        )?;
        Ok(secret)
    }

    /// The hashes of every auth key, for checking a joining machine's
    /// opening request (see [`crate::knock`]). Used, expired and revoked
    /// ones too: their holders then get SSH, and the reason they can't join.
    pub fn authkey_hashes(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT hash FROM authkeys")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn authkeys(&self) -> Result<Vec<AuthKeyRow>> {
        let mut st = self.conn.prepare(
            "SELECT k.id, a.name, k.prefix, k.reusable, k.expires, k.used, k.revoked, k.created, k.ephemeral, k.preapproved
             FROM authkeys k JOIN accounts a ON a.id = k.account_id ORDER BY k.id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(AuthKeyRow {
                    id: r.get(0)?,
                    account: r.get(1)?,
                    prefix: r.get(2)?,
                    reusable: r.get(3)?,
                    expires: r.get(4)?,
                    used: r.get(5)?,
                    revoked: r.get(6)?,
                    created: r.get(7)?,
                    ephemeral: r.get(8)?,
                    preapproved: r.get(9)?,
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

    // ---- access rules ----

    pub fn rules(&self) -> Result<Vec<RuleRow>> {
        let mut st = self.conn.prepare(
            "SELECT r.id, r.account_id, a.name, r.src, r.dst, r.ports
             FROM rules r JOIN accounts a ON a.id = r.account_id ORDER BY a.name, r.id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(RuleRow {
                    id: r.get(0)?,
                    account_id: r.get(1)?,
                    account: r.get(2)?,
                    src: r.get(3)?,
                    dst: r.get(4)?,
                    ports: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn add_rule(&self, account: &str, src: &str, dst: &str, ports: &str) -> Result<i64> {
        let a = self.account(account)?;
        let r = Rule::compile(src, dst, ports)?;
        self.conn.execute(
            "INSERT INTO rules(account_id, src, dst, ports, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                a.id,
                r.from.to_string(),
                r.to.to_string(),
                r.ports.to_string(),
                now_unix()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn delete_rule(&self, id: i64) -> Result<()> {
        if self.conn.execute("DELETE FROM rules WHERE id = ?1", [id])? == 0 {
            bail!("no rule with id {id}");
        }
        Ok(())
    }

    // ---- shares ----

    pub fn shares(&self) -> Result<Vec<ShareRow>> {
        let mut st = self.conn.prepare(&format!("{SHARE_SELECT} ORDER BY s.id"))?;
        let rows = st.query_map([], row_to_share)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Offer machine `node_id` to `account`. Pending until accepted.
    pub fn create_share(&self, node_id: i64, account: &str, ports: &str) -> Result<i64> {
        let n = self.node(node_id)?;
        let a = self.account(account)?;
        if a.id == n.account_id {
            bail!("{} already belongs to account {}", n.name, a.name);
        }
        let ports = Access::parse(ports)?.to_string();
        let r = self.conn.execute(
            "INSERT INTO shares(node_id, account_id, ports, created) VALUES (?1, ?2, ?3, ?4)",
            params![node_id, a.id, ports, now_unix()],
        );
        match r {
            Ok(_) => Ok(self.conn.last_insert_rowid()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                bail!("{}.{} is already shared with {}", n.name, n.account, a.name)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn accept_share(&self, id: i64) -> Result<()> {
        if self
            .conn
            .execute("UPDATE shares SET accepted = 1 WHERE id = ?1", [id])?
            == 0
        {
            bail!("no share with id {id}");
        }
        Ok(())
    }

    pub fn set_share_ports(&self, id: i64, ports: &str) -> Result<String> {
        let ports = Access::parse(ports)?.to_string();
        if self
            .conn
            .execute("UPDATE shares SET ports = ?1 WHERE id = ?2", params![ports, id])?
            == 0
        {
            bail!("no share with id {id}");
        }
        Ok(ports)
    }

    /// Let the share's account use the machine as its exit node, or not.
    pub fn set_share_exit(&self, id: i64, on: bool) -> Result<()> {
        if self
            .conn
            .execute("UPDATE shares SET exit = ?1 WHERE id = ?2", params![on, id])?
            == 0
        {
            bail!("no share with id {id}");
        }
        Ok(())
    }

    pub fn revoke_share(&self, id: i64) -> Result<()> {
        if self.conn.execute("DELETE FROM shares WHERE id = ?1", [id])? == 0 {
            bail!("no share with id {id}");
        }
        Ok(())
    }

    pub fn share(&self, id: i64) -> Result<ShareRow> {
        self.conn
            .query_row(&format!("{SHARE_SELECT} WHERE s.id = ?1"), [id], row_to_share)
            .optional()?
            .with_context(|| format!("no share with id {id}"))
    }

    // ---- share links ----

    /// Create a single-use link sharing `node_id`. Returns the secret, shown once.
    pub fn create_share_link(&self, node_id: i64, ports: &str, expires: i64) -> Result<String> {
        self.node(node_id)?;
        let ports = Access::parse(ports)?.to_string();
        let secret = format!("tc-share-{}", hex::encode(rand::random::<[u8; 18]>()));
        let prefix: String = secret.chars().take(17).collect();
        self.conn.execute(
            "INSERT INTO share_links(hash, prefix, node_id, ports, expires, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![hash_key(&secret), prefix, node_id, ports, expires, now_unix()],
        )?;
        Ok(secret)
    }

    pub fn share_links(&self) -> Result<Vec<ShareLinkRow>> {
        let mut st = self.conn.prepare(
            "SELECT l.id, l.prefix, l.node_id, n.name, o.id, o.name, l.ports, l.expires, u.name, l.revoked, l.created
             FROM share_links l JOIN nodes n ON n.id = l.node_id JOIN accounts o ON o.id = n.account_id
             LEFT JOIN accounts u ON u.id = l.used_by ORDER BY l.id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(ShareLinkRow {
                    id: r.get(0)?,
                    prefix: r.get(1)?,
                    node_id: r.get(2)?,
                    node: r.get(3)?,
                    owner_id: r.get(4)?,
                    owner: r.get(5)?,
                    ports: r.get(6)?,
                    expires: r.get(7)?,
                    used_by: r.get(8)?,
                    revoked: r.get(9)?,
                    created: r.get(10)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn revoke_share_link(&self, id: i64) -> Result<()> {
        if self
            .conn
            .execute("UPDATE share_links SET revoked = 1 WHERE id = ?1", [id])?
            == 0
        {
            bail!("no share link with id {id}");
        }
        Ok(())
    }

    /// Redeem a share link for `account_id`: an accepted share. Returns its id.
    pub fn redeem_share_link(&mut self, code: &str, account_id: i64) -> Result<i64> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let link: Option<(i64, i64, String, i64, Option<i64>, bool)> = tx
            .query_row(
                "SELECT id, node_id, ports, expires, used_by, revoked FROM share_links WHERE hash = ?1",
                [hash_key(code)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?;
        let Some((id, node_id, ports, expires, used_by, revoked)) = link else {
            bail!("invalid share link");
        };
        if revoked || used_by.is_some() || expires <= now_unix() {
            bail!("this share link has been used, revoked or has expired");
        }
        let owner: i64 = tx.query_row("SELECT account_id FROM nodes WHERE id = ?1", [node_id], |r| r.get(0))?;
        if owner == account_id {
            bail!("this machine already belongs to your account");
        }
        tx.execute(
            "UPDATE share_links SET used_by = ?1 WHERE id = ?2",
            params![account_id, id],
        )?;
        // An existing share (perhaps pending) is replaced by the link's.
        tx.execute(
            "DELETE FROM shares WHERE node_id = ?1 AND account_id = ?2",
            params![node_id, account_id],
        )?;
        tx.execute(
            "INSERT INTO shares(node_id, account_id, ports, accepted, created) VALUES (?1, ?2, ?3, 1, ?4)",
            params![node_id, account_id, ports, now_unix()],
        )?;
        let share = tx.last_insert_rowid();
        tx.commit()?;
        Ok(share)
    }

    // ---- invites ----

    pub fn create_invite(&self, expires: i64) -> Result<String> {
        let secret = format!("tc-invite-{}", hex::encode(rand::random::<[u8; 18]>()));
        let prefix: String = secret.chars().take(18).collect();
        self.conn.execute(
            "INSERT INTO invites(hash, prefix, expires, created) VALUES (?1, ?2, ?3, ?4)",
            params![hash_key(&secret), prefix, expires, now_unix()],
        )?;
        Ok(secret)
    }

    pub fn invites(&self) -> Result<Vec<InviteRow>> {
        let mut st = self.conn.prepare(
            "SELECT i.id, i.prefix, i.expires, u.name, i.revoked, i.created
             FROM invites i LEFT JOIN accounts u ON u.id = i.used_by ORDER BY i.id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(InviteRow {
                    id: r.get(0)?,
                    prefix: r.get(1)?,
                    expires: r.get(2)?,
                    used_by: r.get(3)?,
                    revoked: r.get(4)?,
                    created: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn revoke_invite(&self, id: i64) -> Result<()> {
        if self
            .conn
            .execute("UPDATE invites SET revoked = 1 WHERE id = ?1", [id])?
            == 0
        {
            bail!("no invite with id {id}");
        }
        Ok(())
    }

    /// Sign up: create an account, consuming `invite` if given. With a valid
    /// invite the account is active; otherwise it gets `status`.
    pub fn sign_up(
        &mut self,
        name: &str,
        password_hash: &str,
        invite: Option<&str>,
        status: Status,
    ) -> Result<AccountRow> {
        let name = valid_account_name(name)?;
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: i64 = tx.query_row("SELECT count(*) FROM accounts WHERE name = ?1", [&name], |r| r.get(0))?;
        if exists > 0 {
            bail!("that name is taken");
        }
        let mut status = status;
        let mut invite_id = None;
        if let Some(code) = invite.map(str::trim).filter(|c| !c.is_empty()) {
            let row: Option<(i64, i64, Option<i64>, bool)> = tx
                .query_row(
                    "SELECT id, expires, used_by, revoked FROM invites WHERE hash = ?1",
                    [hash_key(code)],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            match row {
                Some((id, expires, None, false)) if expires > now_unix() => {
                    invite_id = Some(id);
                    status = Status::Active;
                }
                _ => bail!("invalid or used invite code"),
            }
        }
        let now = now_unix();
        tx.execute(
            "INSERT INTO accounts(name, created, status, role, password_hash, changed) VALUES (?1, ?2, ?3, 'tenant', ?4, ?2)",
            params![name, now, status.as_str(), password_hash],
        )?;
        let id = tx.last_insert_rowid();
        if let Some(i) = invite_id {
            tx.execute("UPDATE invites SET used_by = ?1 WHERE id = ?2", params![id, i])?;
        }
        tx.commit()?;
        self.account_by_id(id)
    }

    // ---- settings ----

    pub fn setting(&self, k: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT v FROM settings WHERE k = ?1", [k], |r| r.get(0))
            .optional()?)
    }

    pub fn set_setting(&self, k: &str, v: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            params![k, v],
        )?;
        Ok(())
    }

    /// Create a new admin token, replacing the old one. Returns the secret.
    pub fn new_admin_token(&self) -> Result<String> {
        let secret = format!("tc-admin-{}", hex::encode(rand::random::<[u8; 24]>()));
        self.set_setting("admin_token_hash", &hash_key(&secret))?;
        self.set_setting("admin_token_changed", &now_unix().to_string())?;
        Ok(secret)
    }

    /// Whether `token` is the admin token; and when the token last changed.
    pub fn check_admin_token(&self, token: &str) -> Result<bool> {
        let Some(h) = self.setting("admin_token_hash")? else {
            return Ok(false);
        };
        Ok(constant_eq(h.as_bytes(), hash_key(token).as_bytes()))
    }

    pub fn admin_token_changed(&self) -> Result<i64> {
        Ok(self
            .setting("admin_token_changed")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }
}

/// The MagicDNS zone of an account: its own domain, or `ACCOUNT.<hub domain>`.
pub fn account_zone(account: &str, dns_domain: Option<&str>, hub_domain: &str) -> String {
    match dns_domain {
        Some(d) => d.to_string(),
        None => format!("{account}.{hub_domain}"),
    }
}

/// Check an account's MagicDNS domain: a DNS name of at least two labels,
/// not the hub's domain nor under it (that's where every account's default
/// zone lives), and, for tenants, ending in an allowed suffix.
pub fn valid_dns_domain(d: &str, hub_domain: &str, suffixes: Option<&[String]>) -> Result<String> {
    let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 || d.len() > 200 || labels.iter().any(|l| valid_label(l, "label").is_err()) {
        bail!("{d:?} isn't a valid domain (at least two labels of a-z, 0-9 and -)");
    }
    if d == hub_domain || d.ends_with(&format!(".{hub_domain}")) {
        bail!("{d} is inside the hub's own domain {hub_domain}; choose another one");
    }
    if let Some(suffixes) = suffixes
        && !suffixes
            .iter()
            .any(|s| d.ends_with(&format!(".{}", s.trim_matches('.'))))
    {
        bail!("choose a domain ending in .{}", suffixes.join(" or ."));
    }
    Ok(d)
}

/// Account names are DNS labels of at most 32 characters (they're part of
/// every machine's name).
pub fn valid_account_name(s: &str) -> Result<String> {
    let n = valid_label(s, "account name")?;
    if n.len() > 32 {
        bail!("account names are at most 32 characters");
    }
    Ok(n)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// An auth key's account and options, once checked and its use counted.
struct UsedKey {
    account_id: i64,
    ephemeral: bool,
    preapproved: bool,
}

fn use_authkey(tx: &Connection, auth_key: &str, now: i64) -> Result<UsedKey> {
    type Row = (i64, i64, bool, Option<i64>, i64, bool, bool, bool);
    let ak: Option<Row> = tx
        .query_row(
            "SELECT id, account_id, reusable, expires, used, revoked, ephemeral, preapproved FROM authkeys WHERE hash = ?1",
            [hash_key(auth_key)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
        )
        .optional()?;
    let Some((id, account_id, reusable, expires, used, revoked, ephemeral, preapproved)) = ak else {
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
    tx.execute("UPDATE authkeys SET used = used + 1 WHERE id = ?1", [id])?;
    Ok(UsedKey {
        account_id,
        ephemeral,
        preapproved,
    })
}

fn all_nodes(conn: &Connection) -> Result<Vec<NodeRow>> {
    let mut st = conn.prepare(&format!("{NODE_SELECT} ORDER BY a.name, n.name"))?;
    let rows = st.query_map([], row_to_node)?.collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn unique_name(conn: &Connection, account_id: i64, base: &str) -> Result<String> {
    let base = sanitise_name(base);
    let mut st = conn.prepare("SELECT name FROM nodes WHERE account_id = ?1")?;
    let taken: HashSet<String> = st
        .query_map([account_id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
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

/// Lowest free address in 100.64.0.0/10 (unique across all accounts),
/// skipping .0, .255 and the DNS address.
fn next_ip(conn: &Connection, pool: (u32, u32)) -> Result<Ipv4Addr> {
    let mut st = conn.prepare("SELECT ip FROM nodes")?;
    let used: HashSet<Ipv4Addr> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok().and_then(|s| s.parse().ok()))
        .collect();
    for n in pool.0..=pool.1 {
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

    fn db_with(accounts: &[&str]) -> Db {
        let db = Db::memory();
        for a in accounts {
            db.create_account(a).unwrap();
        }
        db
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(sanitise_name("Richard's MacBook Pro"), "richard-s-macbook-pro");
        assert_eq!(sanitise_name("--"), "node");
    }

    #[test]
    fn names_unique_per_account_ips_unique_globally() {
        let mut db = db_with(&["richard", "alice"]);
        let kr = db.create_authkey("richard", true, None).unwrap();
        let ka = db.create_authkey("alice", true, None).unwrap();
        let a = db.register("ssh-ed25519 A", "box", &kr).unwrap();
        let b = db.register("ssh-ed25519 B", "box", &kr).unwrap();
        let c = db.register("ssh-ed25519 C", "box", &ka).unwrap();
        assert_eq!(
            (a.name.as_str(), a.account.as_str(), a.ip),
            ("box", "richard", Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!((b.name.as_str(), b.ip), ("box-2", Ipv4Addr::new(100, 64, 0, 2)));
        assert_eq!(
            (c.name.as_str(), c.account.as_str(), c.ip),
            ("box", "alice", Ipv4Addr::new(100, 64, 0, 3))
        );
        assert_eq!(db.find_node("box.alice").unwrap().id, c.id);
        assert!(db.rename_node(b.id, "box").is_err());
    }

    #[test]
    fn single_use_and_revoked_keys() {
        let mut db = db_with(&["r"]);
        let k = db.create_authkey("r", false, None).unwrap();
        db.register("ssh-ed25519 A", "a", &k).unwrap();
        assert!(db.register("ssh-ed25519 B", "b", &k).is_err());
        let k2 = db.create_authkey("r", true, None).unwrap();
        let id = db.authkeys().unwrap().last().unwrap().id;
        db.revoke_authkey(id).unwrap();
        assert!(db.register("ssh-ed25519 C", "c", &k2).is_err());
        let k3 = db.create_authkey("r", true, Some(now_unix() - 1)).unwrap();
        assert!(db.register("ssh-ed25519 D", "d", &k3).is_err());
        assert!(db.register("ssh-ed25519 E", "e", "tckey-bogus").is_err());
    }

    #[test]
    fn shares_rules_and_account_deletion() {
        let mut db = db_with(&["richard", "alice"]);
        let k = db.create_authkey("richard", true, None).unwrap();
        let web = db.register("ssh-ed25519 W", "web", &k).unwrap();
        assert!(db.create_share(web.id, "richard", "*").is_err(), "own account");
        let s = db.create_share(web.id, "alice", "tcp:443, tcp:80").unwrap();
        assert!(db.create_share(web.id, "alice", "*").is_err(), "duplicate");
        assert_eq!(db.shares().unwrap()[0].ports, "tcp:80,tcp:443");
        assert!(!db.shares().unwrap()[0].accepted);
        db.accept_share(s).unwrap();
        assert!(db.shares().unwrap()[0].accepted);
        assert!(db.add_rule("richard", "tag:staff", "tag:server", "tcp:22").is_ok());
        assert!(db.add_rule("richard", "tag:", "*", "*").is_err());
        assert_eq!(
            db.set_tags(web.id, &["Server".into(), "tag:web".into()]).unwrap(),
            vec!["server", "web"]
        );
        db.delete_account("richard").unwrap();
        assert!(db.nodes().unwrap().is_empty() && db.shares().unwrap().is_empty() && db.rules().unwrap().is_empty());
    }

    #[test]
    fn address_pool() {
        assert_eq!(parse_pool("100.96.0.0/16").unwrap(), (0x6460_0000, 0x6460_ffff));
        assert!(parse_pool("10.0.0.0/8").is_err());
        assert!(parse_pool("100.64.0.0/9").is_err());
        let mut db = db_with(&["r"]);
        db.set_pool(parse_pool("100.96.0.0/24").unwrap());
        let k = db.create_authkey("r", true, None).unwrap();
        assert_eq!(
            db.register("ssh-ed25519 A", "a", &k).unwrap().ip,
            Ipv4Addr::new(100, 96, 0, 1)
        );
    }

    #[test]
    fn expiry_approval_and_ephemeral_keys() {
        let mut db = db_with(&["r"]);
        db.set_key_expiry(Some(3600));
        let k = db.create_authkey("r", true, None).unwrap();
        let a = db.register("ssh-ed25519 A", "a", &k).unwrap();
        let now = now_unix();
        assert!(a.expires.unwrap() > now + 3500 && a.approved && !a.ephemeral);
        // Approval required: new machines wait, unless the key is pre-approved.
        db.set_require_approval("r", true).unwrap();
        assert!(!db.register("ssh-ed25519 B", "b", &k).unwrap().approved);
        let pre = db.create_authkey_with("r", true, None, true, true).unwrap();
        let c = db.register("ssh-ed25519 C", "c", &pre).unwrap();
        assert!(c.approved && c.ephemeral);
        // Expired: renewed by an auth key of its own account.
        db.set_node_expiry(a.id, Some(now - 1)).unwrap();
        assert!(db.node(a.id).unwrap().expired(now));
        let renewed = db.reauthorize("ssh-ed25519 A", &k).unwrap();
        assert!(!renewed.expired(now));
        db.create_account("other").unwrap();
        let ko = db.create_authkey("other", true, None).unwrap();
        assert!(db.reauthorize("ssh-ed25519 A", &ko).is_err(), "another account's key");
        // Never-expiring machines stay that way; approval with a pre-approved key.
        db.set_node_expiry(a.id, None).unwrap();
        assert_eq!(db.reauthorize("ssh-ed25519 A", &k).unwrap().expires, None);
        let b = db.reauthorize("ssh-ed25519 B", &pre).unwrap();
        assert!(b.approved);
        // Keys without expiry for the server ("never").
        db.set_key_expiry(None);
        let d = db.register("ssh-ed25519 D", "d", &pre).unwrap();
        assert_eq!(d.expires, None);
    }

    #[test]
    fn account_dns_domains() {
        let db = db_with(&["alice", "bob"]);
        let tenant = vec!["internal".to_string()];
        let t = Some(tenant.as_slice());
        assert_eq!(
            db.set_dns_domain("alice", Some("Acme.Internal."), "tc.internal", t)
                .unwrap(),
            Some("acme.internal".into())
        );
        assert_eq!(
            db.account("alice").unwrap().dns_domain.as_deref(),
            Some("acme.internal")
        );
        assert!(
            db.set_dns_domain("bob", Some("acme.internal"), "tc.internal", t)
                .is_err(),
            "taken"
        );
        assert!(
            db.set_dns_domain("bob", Some("bob.example.com"), "tc.internal", t)
                .is_err(),
            "tenant suffix"
        );
        assert!(
            db.set_dns_domain("bob", Some("bob.example.com"), "tc.internal", None)
                .is_ok(),
            "operators: any"
        );
        assert!(
            db.set_dns_domain("bob", Some("x.tc.internal"), "tc.internal", None)
                .is_err(),
            "inside the hub's domain"
        );
        assert!(
            db.set_dns_domain("bob", Some("internal"), "tc.internal", None).is_err(),
            "one label"
        );
        assert_eq!(
            db.set_dns_domain("alice", Some(""), "tc.internal", t).unwrap(),
            None,
            "back to default"
        );
        assert_eq!(account_zone("alice", None, "tc.internal"), "alice.tc.internal");
        assert_eq!(
            account_zone("alice", Some("acme.internal"), "tc.internal"),
            "acme.internal"
        );
    }

    #[test]
    fn migrates_version_1() {
        let path = std::env::temp_dir().join(format!("tc-migrate1-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA_V1).unwrap();
            c.execute_batch(
                "INSERT INTO accounts(name, status, created) VALUES ('richard', 'active', 1);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let a = db.account("richard").unwrap();
        assert_eq!(
            (a.role, a.has_password, a.status),
            (Role::Tenant, false, Status::Active)
        );
        assert!(db.invites().unwrap().is_empty() && db.share_links().unwrap().is_empty());
        assert!(db.setting("admin_token_hash").unwrap().is_none());
        drop(db);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn migrates_version_0() {
        let path = std::env::temp_dir().join(format!("tc-migrate-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE nodes(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL UNIQUE,
                    key TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL, created INTEGER NOT NULL, last_seen INTEGER);
                 CREATE TABLE authkeys(id INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL,
                    reusable INTEGER NOT NULL, expires INTEGER, used INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
                 INSERT INTO nodes VALUES (7, 'alpha', '100.64.0.1', 'ssh-ed25519 A', 'alpha', 1, 2);
                 INSERT INTO authkeys VALUES (3, 'h', 'tckey-x', 1, NULL, 1, 0, 1);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let n = db.node(7).unwrap();
        assert_eq!((n.name.as_str(), n.account.as_str()), ("alpha", DEFAULT_ACCOUNT));
        assert_eq!(db.authkeys().unwrap()[0].account, DEFAULT_ACCOUNT);
        drop(db);
        Db::open(&path).unwrap(); // idempotent
        std::fs::remove_file(&path).unwrap();
    }
}
