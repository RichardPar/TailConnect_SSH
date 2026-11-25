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
}

/// One entry of a machine's network map.
pub struct Peer<'a> {
    pub node: &'a SNode,
    /// What this peer may open on the machine.
    pub inbound: Access,
}

impl Snapshot {
    pub fn load(db: &Db) -> Result<Self> {
        let accounts: HashMap<i64, Status> = db.accounts()?.into_iter().map(|a| (a.id, a.status)).collect();
        let nodes: Vec<SNode> = db
            .nodes()?
            .into_iter()
            .map(|n| SNode {
                id: n.id,
                active: accounts.get(&n.account_id) == Some(&Status::Active),
                account_id: n.account_id,
                account: n.account,
                name: n.name,
                ip: n.ip,
                key: n.key,
                tags: n.tags,
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
            out.push(Peer { node: p, inbound });
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
