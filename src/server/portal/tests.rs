//! Portal API tests, in process (no network).

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::server::auth::hash_password;

const HOST: &str = "hub.example";
const PW: &str = "correct horse battery";

struct T {
    router: Router,
    portal: Arc<Portal>,
}

struct Resp {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
    headers: axum::http::HeaderMap,
}

impl T {
    fn new(signup: Signup) -> Self {
        let db = Db::memory();
        let h = hash_password(PW).unwrap();
        db.create_account_with("richard", Status::Active, Role::Operator, Some(&h))
            .unwrap();
        db.create_account_with("alice", Status::Active, Role::Tenant, Some(&h))
            .unwrap();
        let cfg = Config {
            signup,
            domain: "tc.internal".into(),
            public_server: String::new(),
            tls_fingerprint: Some("ab".repeat(32)),
            hosts: vec![HOST.into()],
        };
        let portal = Portal::new(cfg, db, Arc::new(HashSet::new));
        T {
            router: router(portal.clone()),
            portal,
        }
    }

    fn db<R>(&self, f: impl FnOnce(&mut Db) -> R) -> R {
        f(&mut self.portal.db.lock().unwrap())
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        cookie: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Resp {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, HOST);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, format!("{SESSION_COOKIE}={c}"));
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let req = b
            .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
            .unwrap();
        let info = ConnInfo {
            peer: "192.0.2.1:5555".parse().unwrap(),
            tls: true,
        };
        let resp = self
            .router
            .clone()
            .layer(axum::Extension(info))
            .oneshot(req)
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .and_then(|v| v.split_once('='))
            .map(|(_, v)| v.to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp {
            status,
            body,
            cookie,
            headers,
        }
    }

    async fn get(&self, path: &str, c: &str) -> Resp {
        self.call("GET", path, None, Some(c), &[]).await
    }

    async fn post(&self, path: &str, body: Value, c: &str) -> Resp {
        self.call("POST", path, Some(body), Some(c), &[]).await
    }

    async fn login(&self, name: &str) -> String {
        let r = self
            .call(
                "POST",
                "/api/login",
                Some(json!({"name": name, "password": PW})),
                None,
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        r.cookie.unwrap()
    }
}

#[tokio::test]
async fn static_pages_and_headers() {
    let t = T::new(Signup::Off);
    let r = t.call("GET", "/", None, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    let csp = r
        .headers
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe"));
    assert!(r.headers.get(header::STRICT_TRANSPORT_SECURITY).is_some());
    assert_eq!(t.call("GET", "/app.js", None, None, &[]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_host_is_refused() {
    let t = T::new(Signup::Off);
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "evil.example")
        .body(Body::empty())
        .unwrap();
    let info = ConnInfo {
        peer: "192.0.2.1:1".parse().unwrap(),
        tls: true,
    };
    let resp = t
        .router
        .clone()
        .layer(axum::Extension(info))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    for ok in ["10.0.0.1", "[::1]:443", "localhost:8443", "HUB.example"] {
        let req = Request::builder()
            .uri("/api/info")
            .header(header::HOST, ok)
            .body(Body::empty())
            .unwrap();
        let resp = t
            .router
            .clone()
            .layer(axum::Extension(info))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{ok}");
    }
}

#[tokio::test]
async fn sign_in_and_out() {
    let t = T::new(Signup::Off);
    let r = t
        .call(
            "POST",
            "/api/login",
            Some(json!({"name": "richard", "password": "wrong password!"})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t
        .call(
            "POST",
            "/api/login",
            Some(json!({"name": "nobody", "password": PW})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let c = t.login("richard").await;
    let me = t.get("/api/me", &c).await;
    assert_eq!(me.body["name"], "richard");
    assert_eq!(me.body["operator"], true);
    assert_eq!(me.body["server"], HOST);
    assert!(t.get("/api/me", "bogus").await.status == StatusCode::UNAUTHORIZED);
    t.post("/api/logout", json!({}), &c).await;
    assert_eq!(t.get("/api/me", &c).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cross_site_and_non_json_writes_are_refused() {
    let t = T::new(Signup::Off);
    let c = t.login("richard").await;
    // Not JSON.
    let r = t
        .call("POST", "/api/keys", None, Some(&c), &[("content-type", "text/plain")])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // JSON, but from another origin.
    let body = Some(json!({"expires_hours": 1}));
    let r = t
        .call(
            "POST",
            "/api/keys",
            body.clone(),
            Some(&c),
            &[("origin", "https://evil.example")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .call(
            "POST",
            "/api/keys",
            body.clone(),
            Some(&c),
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .call(
            "POST",
            "/api/keys",
            body,
            Some(&c),
            &[("origin", "https://hub.example")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

#[tokio::test]
async fn guesses_are_limited() {
    let t = T::new(Signup::Off);
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        last = t
            .call(
                "POST",
                "/api/login",
                Some(json!({"name": "alice", "password": "nope nope nope"})),
                None,
                &[],
            )
            .await
            .status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn tenants_see_only_their_own_account() {
    let t = T::new(Signup::Off);
    let (rich_m, alice_m) = t.db(|db| {
        let kr = db.create_authkey("richard", true, None).unwrap();
        let ka = db.create_authkey("alice", true, None).unwrap();
        let r = db.register("ssh-ed25519 R", "web", &kr).unwrap();
        let a = db.register("ssh-ed25519 A", "laptop", &ka).unwrap();
        (r.id, a.id)
    });
    let ca = t.login("alice").await;
    let ms = t.get("/api/machines", &ca).await.body;
    assert_eq!(ms.as_array().unwrap().len(), 1);
    assert_eq!(ms[0]["fqdn"], "laptop.alice.tc.internal");
    // richard's machine looks like it doesn't exist.
    let r = t
        .post(&format!("/api/machines/{rich_m}/rename"), json!({"name": "x"}), &ca)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .post(
            &format!("/api/machines/{alice_m}/tags"),
            json!({"tags": "Laptop, staff"}),
            &ca,
        )
        .await;
    assert_eq!(r.body["tags"], json!(["laptop", "staff"]));
    // Operator pages.
    assert_eq!(t.get("/api/accounts", &ca).await.status, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/invites", &ca).await.status, StatusCode::FORBIDDEN);
    // Keys and rules for another account.
    let r = t
        .post("/api/keys", json!({"account": "richard", "expires_hours": 1}), &ca)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.get("/api/rules?account=richard", &ca).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .post("/api/keys", json!({"expires_hours": 24, "reusable": true}), &ca)
        .await;
    assert!(r.body["key"].as_str().unwrap().starts_with("tckey-"));
    assert_eq!(
        t.get("/api/keys", &ca).await.body.as_array().unwrap().len(),
        2,
        "alice's key from setup and this one"
    );
    // The operator sees everything.
    let cr = t.login("richard").await;
    assert_eq!(t.get("/api/machines", &cr).await.body.as_array().unwrap().len(), 2);
    assert_eq!(t.get("/api/keys", &cr).await.body.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn rules_from_the_portal() {
    let t = T::new(Signup::Off);
    let c = t.login("alice").await;
    let r = t
        .post(
            "/api/rules",
            json!({"from": "tag:staff", "to": "tag:server", "ports": "tcp:22"}),
            &c,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .post("/api/rules", json!({"from": "tag:", "to": "*", "ports": "*"}), &c)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let rules = t.get("/api/rules", &c).await.body;
    assert_eq!(rules["account"], "alice");
    let id = rules["rules"][0]["id"].as_i64().unwrap();
    let cr = t.login("richard").await;
    assert_eq!(
        t.get("/api/rules?account=alice", &cr).await.body["rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        t.call("DELETE", &format!("/api/rules/{id}"), Some(json!({})), Some(&c), &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sharing_by_name_and_by_link() {
    let t = T::new(Signup::Off);
    let (web, nas) = t.db(|db| {
        db.create_account_with("bob", Status::Active, Role::Tenant, Some(&hash_password(PW).unwrap()))
            .unwrap();
        let kr = db.create_authkey("richard", true, None).unwrap();
        let ka = db.create_authkey("alice", true, None).unwrap();
        (
            db.register("ssh-ed25519 W", "web", &kr).unwrap().id,
            db.register("ssh-ed25519 N", "nas", &ka).unwrap().id,
        )
    });
    let cr = t.login("richard").await;
    let ca = t.login("alice").await;
    let cb = t.login("bob").await;
    // alice can't share richard's machine.
    let r = t
        .post("/api/shares", json!({"node_id": web, "account": "bob"}), &ca)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // richard shares web with alice; alice accepts.
    let r = t
        .post(
            "/api/shares",
            json!({"node_id": web, "account": "alice", "ports": "tcp:80,tcp:443"}),
            &cr,
        )
        .await;
    let sid = r.body["id"].as_i64().unwrap();
    let with = t.get("/api/shares", &ca).await.body;
    assert_eq!(with["with_me"][0]["status"], "pending");
    assert_eq!(
        t.post(&format!("/api/shares/{sid}/accept"), json!({}), &cb)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.post(&format!("/api/shares/{sid}/accept"), json!({}), &ca)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(t.get("/api/shares", &ca).await.body["with_me"][0]["status"], "active");
    // Only the owner changes ports.
    let r = t
        .post(&format!("/api/shares/{sid}/ports"), json!({"ports": "tcp:443"}), &ca)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // alice shares nas with bob by link.
    let r = t
        .post("/api/share-links", json!({"node_id": nas, "ports": "", "days": 7}), &ca)
        .await;
    let code = r.body["code"].as_str().unwrap().to_string();
    assert!(code.starts_with("tc-share-"));
    let r = t.post("/api/share-links/redeem", json!({"code": code}), &ca).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "own machine");
    let r = t.post("/api/share-links/redeem", json!({"code": code}), &cb).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.post("/api/share-links/redeem", json!({"code": code}), &cr).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "single use");
    let bob = t.get("/api/shares", &cb).await.body;
    assert_eq!(bob["with_me"][0]["machine"], "nas.alice");
    assert_eq!(bob["with_me"][0]["ports"], "*");
    // The recipient can remove a share.
    let bid = bob["with_me"][0]["id"].as_i64().unwrap();
    assert_eq!(
        t.call("DELETE", &format!("/api/shares/{bid}"), Some(json!({})), Some(&cb), &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sign_up_with_approval_and_invites() {
    let t = T::new(Signup::Approval);
    let r = t
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "carol", "password": PW})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.body["status"], "pending");
    let r = t
        .call(
            "POST",
            "/api/login",
            Some(json!({"name": "carol", "password": PW})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body["error"].as_str().unwrap().contains("approval"));
    let r = t
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "carol", "password": PW})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "taken");
    let r = t
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "dave", "password": "short"})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // The operator approves carol and invites erin.
    let cr = t.login("richard").await;
    let carol = t
        .get("/api/accounts", &cr)
        .await
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "carol")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    t.post(
        &format!("/api/accounts/{carol}/status"),
        json!({"status": "active"}),
        &cr,
    )
    .await;
    t.login("carol").await;
    let code = t.post("/api/invites", json!({"days": 7}), &cr).await.body["code"]
        .as_str()
        .unwrap()
        .to_string();
    let r = t
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "erin", "password": PW, "invite": code})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.body["status"], "active");
    assert!(r.cookie.is_some(), "signed in at once");
    let r = t
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "frank", "password": PW, "invite": code})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "invite used");

    let off = T::new(Signup::Off);
    let r = off
        .call(
            "POST",
            "/api/signup",
            Some(json!({"name": "zed", "password": PW})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn password_role_and_status_changes_end_sessions() {
    let t = T::new(Signup::Off);
    let c1 = t.login("alice").await;
    let c2 = t.login("alice").await;
    // Sessions are compared with one-second resolution.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let r = t
        .post(
            "/api/me/password",
            json!({"current": "wrong wrong wrong", "new": "another long password"}),
            &c1,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = t
        .post(
            "/api/me/password",
            json!({"current": PW, "new": "another long password"}),
            &c1,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let c3 = r.cookie.unwrap();
    assert_eq!(
        t.get("/api/me", &c2).await.status,
        StatusCode::UNAUTHORIZED,
        "other session ended"
    );
    assert_eq!(
        t.get("/api/me", &c3).await.status,
        StatusCode::OK,
        "this one carries on"
    );

    let cr = t.login("richard").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let alice = t.db(|db| db.account("alice").unwrap().id);
    t.post(
        &format!("/api/accounts/{alice}/status"),
        json!({"status": "suspended"}),
        &cr,
    )
    .await;
    assert_eq!(t.get("/api/me", &c3).await.status, StatusCode::UNAUTHORIZED);
    // An operator can't lock themselves out.
    let me = t.db(|db| db.account("richard").unwrap().id);
    assert_eq!(
        t.post(&format!("/api/accounts/{me}/role"), json!({"role": "tenant"}), &cr)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        t.call(
            "DELETE",
            &format!("/api/accounts/{me}"),
            Some(json!({})),
            Some(&cr),
            &[]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn admin_token() {
    let t = T::new(Signup::Off);
    let tok = t.db(|db| db.new_admin_token().unwrap());
    let r = t
        .call(
            "POST",
            "/api/login",
            Some(json!({"admin_token": "tc-admin-wrong"})),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t
        .call("POST", "/api/login", Some(json!({"admin_token": tok})), None, &[])
        .await;
    let c = r.cookie.unwrap();
    let me = t.get("/api/me", &c).await.body;
    assert_eq!(
        (me["operator"].clone(), me["admin_token"].clone()),
        (json!(true), json!(true))
    );
    assert_eq!(t.get("/api/accounts", &c).await.status, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    t.db(|db| db.new_admin_token().unwrap());
    assert_eq!(
        t.get("/api/me", &c).await.status,
        StatusCode::UNAUTHORIZED,
        "replacing the token ends its sessions"
    );
}
