//! Who may talk to whom: accounts, access rules and shares, compiled from
//! one consistent read of the database.
//!
//! For a machine N, its peers are:
//!
//! * machines of its own account that the account's rules let talk to N in
//!   either direction (all of them, if the account has no rules);
//! * machines shared with N's account;
//! * if N is shared with other accounts, those accounts' machines, so their
//!   connections can be answered.
//!
//! For each peer P the hub tells N what P may open on N ("inbound"). N's
//! packet filter enforces it. Machines of suspended accounts take no part.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::Result;

use super::db::{Db, Status};
use crate::acl::{Access, Rule};

#[derive(Debug, Clone)]
pub struct SNode {
    pub id: i64,
    pub account_id: i64,
    pub account: String,
    pub active: bool,
    pub name: String,
    pub ip: Ipv4Addr,
    pub key: String,
    pub tags: Vec<String>,
    pub exit_node: bool,
    /// Why the machine is cut off from the network (`active` is false):
    /// its account is suspended or pending, it waits for approval, or its
    /// key expired. It keeps its keys and connection, and gets an empty map
    /// with this as the notice.
    pub cutoff: Option<String>,
    pub expires: Option<i64>,
}

/// An account's compiled rules. `None`: no rules, everything allowed.
/// `Some(Err)`: a stored rule doesn't compile, so nothing is allowed.
type Policy = Option<Result<Vec<Rule>, ()>>;

#[derive(Default)]
pub struct Snapshot {
    pub nodes: Vec<SNode>,
    by_ip: HashMap<Ipv4Addr, usize>,
    by_key: HashMap<String, usize>,
    policies: HashMap<i64, Policy>,
    /// Accepted shares between active accounts: (node, recipient account) → ports.
    shares: HashMap<(i64, i64), Access>,
    /// The next moment a machine's key expires: the snapshot must be rebuilt
    /// then, although nothing in the database changes.
    pub next_expiry: Option<i64>,
}

/// One entry of a machine's network map.
pub struct Peer<'a> {
    pub node: &'a SNode,
    /// What this peer may open on the machine.
    pub inbound: Access,
    /// The peer offers to be the machine's exit node.
    pub exit_node: bool,
}

impl Snapshot {
    pub fn load(db: &Db) -> Result<Self> {
        let now = crate::now_unix();
        let mut next_expiry: Option<i64> = None;
        let accounts: HashMap<i64, Status> = db.accounts()?.into_iter().map(|a| (a.id, a.status)).collect();
        let nodes: Vec<SNode> = db
            .nodes()?
            .into_iter()
            .map(|n| {
                let cutoff = match accounts.get(&n.account_id) {
                    Some(Status::Active) => None,
                    Some(Status::Pending) => Some(format!("account {} is waiting for approval", n.account)),
                    _ => Some(format!("account {} is suspended", n.account)),
                }
                .or_else(|| {
                    (!n.approved).then(|| {
                        format!(
                            "this machine is waiting for approval by account {} or an operator",
                            n.account
                        )
                    })
                })
                .or_else(|| {
                    n.expired(now)
                        .then(|| "this machine's key has expired: renew it with `tcs up --authkey KEY`".to_string())
                });
                if let Some(e) = n.expires.filter(|e| *e > now) {
                    next_expiry = Some(next_expiry.map_or(e, |x: i64| x.min(e)));
                }
                SNode {
                    id: n.id,
                    active: cutoff.is_none(),
                    cutoff,
                    expires: n.expires,
                    account_id: n.account_id,
                    account: n.account,
                    name: n.name,
                    ip: n.ip,
                    key: n.key,
                    tags: n.tags,
                    exit_node: n.exit_node,
                }
            })
            .collect();
        let mut policies: HashMap<i64, Policy> = HashMap::new();
        for r in db.rules()? {
            let entry = policies.entry(r.account_id).or_insert_with(|| Some(Ok(Vec::new())));
            match (entry, Rule::compile(&r.src, &r.dst, &r.ports)) {
                (Some(Ok(v)), Ok(rule)) => v.push(rule),
                (e, Err(err)) => {
                    tracing::warn!(
                        "access rule {} of {} doesn't compile ({err}): denying all",
                        r.id,
                        r.account
                    );
                    *e = Some(Err(()));
                }
                (Some(Err(())), Ok(_)) => {}
                (None, _) => unreachable!(),
            }
        }
        let active_node: HashMap<i64, bool> = nodes.iter().map(|n| (n.id, n.active)).collect();
        let mut shares = HashMap::new();
        for s in db.shares()? {
            let both_active =
                active_node.get(&s.node_id) == Some(&true) && accounts.get(&s.account_id) == Some(&Status::Active);
            if !s.accepted || !both_active {
                continue;
            }
            // A share whose ports don't parse grants nothing.
            let ports = Access::parse(&s.ports).unwrap_or_default();
            shares
                .entry((s.node_id, s.account_id))
                .or_insert_with(Access::none)
                .union(&ports);
        }
        let by_ip = nodes.iter().enumerate().map(|(i, n)| (n.ip, i)).collect();
        let by_key = nodes.iter().enumerate().map(|(i, n)| (n.key.clone(), i)).collect();
        Ok(Snapshot {
            nodes,
            by_ip,
            by_key,
            policies,
            shares,
            next_expiry,
        })
    }

    pub fn by_key(&self, key: &str) -> Option<&SNode> {
        self.by_key.get(key).map(|&i| &self.nodes[i])
    }

    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<&SNode> {
        self.by_ip.get(&ip).map(|&i| &self.nodes[i])
    }

    /// What `from` may open on `to`, both in the same account.
    fn rule_access(&self, from: &SNode, to: &SNode) -> Access {
        match self.policies.get(&from.account_id) {
            None | Some(None) => Access::All,
            Some(Some(Err(()))) => Access::none(),
            Some(Some(Ok(rules))) => {
                let mut a = Access::none();
                for r in rules {
                    if r.from.matches(&from.name, &from.tags) && r.to.matches(&to.name, &to.tags) {
                        a.union(&r.ports);
                    }
                }
                a
            }
        }
    }

    /// What `from` may open on `to`.
    pub fn access(&self, from: &SNode, to: &SNode) -> Access {
        if !from.active || !to.active || from.id == to.id {
            return Access::none();
        }
        if from.account_id == to.account_id {
            return self.rule_access(from, to);
        }
        self.shares.get(&(to.id, from.account_id)).cloned().unwrap_or_default()
    }

    /// May `user` send its internet traffic through `exit`? Only within one
    /// account, and only if `user` may open everything on `exit` (access
    /// rules that limit it rule it out).
    pub fn exit_for(&self, exit: &SNode, user: &SNode) -> bool {
        exit.exit_node && exit.account_id == user.account_id && self.access(user, exit).is_all()
    }

    /// The network map of `me`, or `None` if its account is suspended.
    pub fn peers_of(&self, me: &SNode) -> Option<Vec<Peer<'_>>> {
        if !me.active {
            return None;
        }
        let mut out = Vec::new();
        for p in &self.nodes {
            if p.id == me.id || !p.active {
                continue;
            }
            let inbound = self.access(p, me);
            if inbound.is_none() && self.access(me, p).is_none() {
                continue;
            }
            out.push(Peer {
                node: p,
                inbound,
                exit_node: self.exit_for(p, me),
            });
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct World {
        db: Db,
        keys: HashMap<String, String>,
    }

    impl World {
        fn new(accounts: &[&str]) -> Self {
            let db = Db::memory();
            let mut keys = HashMap::new();
            for a in accounts {
                db.create_account(a).unwrap();
                keys.insert(a.to_string(), db.create_authkey(a, true, None).unwrap());
            }
            World { db, keys }
        }

        fn add(&mut self, account: &str, name: &str) -> i64 {
            let k = self.keys[account].clone();
            self.db
                .register(&format!("ssh-ed25519 {name}.{account}"), name, &k)
                .unwrap()
                .id
        }

        /// `me`'s peers as "name.account=inbound".
        fn map(&self, me: i64) -> Vec<String> {
            let s = Snapshot::load(&self.db).unwrap();
            let me = s.nodes.iter().find(|n| n.id == me).unwrap();
            let mut v: Vec<String> = s
                .peers_of(me)
                .map(|ps| {
                    ps.iter()
                        .map(|p| format!("{}.{}={}", p.node.name, p.node.account, p.inbound))
                        .collect()
                })
                .unwrap_or_else(|| vec!["suspended".into()]);
            v.sort();
            v
        }
    }

    #[test]
    fn accounts_are_isolated() {
        let mut w = World::new(&["richard", "alice"]);
        let a = w.add("richard", "a");
        w.add("richard", "b");
        let c = w.add("alice", "c");
        assert_eq!(w.map(a), vec!["b.richard=*"]);
        assert!(w.map(c).is_empty());
    }

    #[test]
    fn shares_are_one_way_and_need_accepting() {
        let mut w = World::new(&["richard", "alice", "bob"]);
        let web = w.add("richard", "web");
        let other = w.add("richard", "other");
        let c = w.add("alice", "c");
        let d = w.add("bob", "d");
        let s = w.db.create_share(web, "alice", "tcp:80,tcp:443").unwrap();
        assert!(w.map(c).is_empty(), "pending share");
        w.db.accept_share(s).unwrap();
        assert_eq!(w.map(c), vec!["web.richard=nothing"], "alice can't be reached from web");
        assert_eq!(w.map(web), vec!["c.alice=tcp:80,tcp:443", "other.richard=*"]);
        assert_eq!(w.map(other), vec!["web.richard=*"], "other machines aren't exposed");
        assert!(w.map(d).is_empty(), "bob sees nothing");
        // Suspending either side ends it.
        w.db.set_account_status("alice", Status::Suspended).unwrap();
        assert_eq!(w.map(web), vec!["other.richard=*"]);
        assert_eq!(w.map(c), vec!["suspended"]);
    }

    #[test]
    fn mutual_shares_give_a_two_way_link() {
        let mut w = World::new(&["richard", "alice"]);
        let x = w.add("richard", "x");
        let y = w.add("alice", "y");
        let s1 = w.db.create_share(x, "alice", "*").unwrap();
        let s2 = w.db.create_share(y, "richard", "tcp:22").unwrap();
        w.db.accept_share(s1).unwrap();
        w.db.accept_share(s2).unwrap();
        assert_eq!(w.map(x), vec!["y.alice=*"]);
        assert_eq!(w.map(y), vec!["x.richard=tcp:22"]);
    }

    #[test]
    fn exit_nodes_serve_their_own_account_when_rules_allow() {
        let mut w = World::new(&["richard", "alice"]);
        let gw = w.add("richard", "gw");
        let laptop = w.add("richard", "laptop");
        let tablet = w.add("richard", "tablet");
        let nas = w.add("alice", "nas");
        w.db.set_exit_node(gw, true).unwrap();
        let s = w.db.create_share(gw, "alice", "*").unwrap();
        w.db.accept_share(s).unwrap();
        let exits = |me: i64| {
            let s = Snapshot::load(&w.db).unwrap();
            let me = s.nodes.iter().find(|n| n.id == me).unwrap();
            let mut v: Vec<String> = s
                .peers_of(me)
                .unwrap()
                .iter()
                .filter(|p| p.exit_node)
                .map(|p| p.node.name.clone())
                .collect();
            v.sort();
            v
        };
        assert_eq!(exits(laptop), vec!["gw"]);
        assert!(
            exits(nas).is_empty(),
            "a share never makes it an exit node for another account"
        );
        // Rules that limit what the tablet may open on gw rule it out.
        w.db.set_tags(laptop, &["staff".into()]).unwrap();
        w.db.add_rule("richard", "tag:staff", "*", "*").unwrap();
        w.db.add_rule("richard", "tablet", "gw", "tcp:443").unwrap();
        assert_eq!(exits(laptop), vec!["gw"]);
        assert!(exits(tablet).is_empty());
        w.db.set_exit_node(gw, false).unwrap();
        assert!(exits(laptop).is_empty());
    }

    #[test]
    fn unapproved_and_expired_machines_are_cut_off() {
        let mut w = World::new(&["richard"]);
        let a = w.add("richard", "a");
        let b = w.add("richard", "b");
        let c = w.add("richard", "c");
        let now = crate::now_unix();
        w.db.set_node_expiry(b, Some(now - 1)).unwrap();
        w.db.set_node_expiry(c, Some(now + 3600)).unwrap();
        w.db.set_require_approval("richard", true).unwrap();
        let d = w.add("richard", "d");
        let s = Snapshot::load(&w.db).unwrap();
        let node = |id| s.nodes.iter().find(|n| n.id == id).unwrap();
        assert!(node(b).cutoff.as_deref().unwrap().contains("expired"));
        assert!(node(d).cutoff.as_deref().unwrap().contains("waiting for approval"));
        assert!(s.peers_of(node(b)).is_none() && s.peers_of(node(d)).is_none());
        assert_eq!(
            w.map(a),
            vec!["c.richard=*"],
            "cut-off machines are invisible to others"
        );
        assert_eq!(s.next_expiry, Some(now + 3600), "the next expiry to rebuild at");
        w.db.approve_node(d).unwrap();
        w.db.set_node_expiry(b, None).unwrap();
        assert_eq!(w.map(a), vec!["b.richard=*", "c.richard=*", "d.richard=*"]);
    }

    #[test]
    fn rules_within_an_account() {
        let mut w = World::new(&["richard"]);
        let laptop = w.add("richard", "laptop");
        let web = w.add("richard", "web");
        let tablet = w.add("richard", "tablet");
        w.db.set_tags(laptop, &["staff".into()]).unwrap();
        w.db.set_tags(web, &["server".into()]).unwrap();
        w.db.add_rule("richard", "tag:staff", "tag:server", "tcp:80,tcp:443")
            .unwrap();
        assert_eq!(w.map(web), vec!["laptop.richard=tcp:80,tcp:443"]);
        assert_eq!(w.map(laptop), vec!["web.richard=nothing"]);
        assert!(w.map(tablet).is_empty(), "no rule mentions the tablet");
        w.db.add_rule("richard", "tablet", "*", "icmp").unwrap();
        assert_eq!(w.map(web), vec!["laptop.richard=tcp:80,tcp:443", "tablet.richard=icmp"]);
    }
}
