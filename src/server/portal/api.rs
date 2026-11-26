//! The portal's JSON API, under `/api`.
//!
//! Tenants act on their own account's machines, keys, rules and shares;
//! operators on every account's. Objects of other accounts look like they
//! don't exist (404).

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ConnInfo, Me, Portal, SESSION_COOKIE, SESSION_TTL, Signup, Who, bearer, cookie};
use crate::now_unix;
use crate::server::auth;
use crate::server::db::{Role, Status};

type P = State<Arc<Portal>>;
type ApiResult = Result<Response, ApiError>;

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(m: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, m.into())
    }
    fn not_found() -> Self {
        ApiError(StatusCode::NOT_FOUND, "not found".into())
    }
    fn forbidden() -> Self {
        ApiError(StatusCode::FORBIDDEN, "operators only".into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::bad(format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn ok(v: Value) -> ApiResult {
    Ok(Json(v).into_response())
}

impl FromRequestParts<Arc<Portal>> for Me {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, p: &Arc<Portal>) -> Result<Self, Self::Rejection> {
        // Scripts: the admin token as a bearer token acts as an operator.
        if let Some(token) = bearer(&parts.headers) {
            if p.db.lock().unwrap().check_admin_token(token).unwrap_or(false) {
                return Ok(Me {
                    account: None,
                    operator: true,
                });
            }
            let ip = parts.extensions.get::<ConnInfo>().map(|c| c.peer.ip());
            if let Some(ip) = ip
                && !p.by_client.take(&auth::client_key(ip))
            {
                return Err(too_many());
            }
            return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token".into()));
        }
        cookie(&parts.headers, SESSION_COOKIE)
            .and_then(|t| p.resolve(&t))
            .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "not signed in".into()))
    }
}

/// Operators only.
struct Op(Me);

impl FromRequestParts<Arc<Portal>> for Op {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, p: &Arc<Portal>) -> Result<Self, Self::Rejection> {
        let me = Me::from_request_parts(parts, p).await?;
        if !me.operator {
            return Err(ApiError::forbidden());
        }
        Ok(Op(me))
    }
}

pub fn routes() -> Router<Arc<Portal>> {
    Router::new()
        .route("/info", get(info))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/signup", post(signup))
        .route("/me", get(me))
        .route("/status", get(status))
        .route("/me/password", post(change_password))
        .route("/machines", get(machines))
        .route("/machines/{id}", delete(remove_machine))
        .route("/machines/{id}/tags", post(tag_machine))
        .route("/machines/{id}/rename", post(rename_machine))
        .route("/machines/{id}/traffic", get(machine_traffic))
        .route("/machines/{id}/exit-node", post(exit_node))
        .route("/machines/{id}/approve", post(approve_machine))
        .route("/machines/{id}/expiry", post(machine_expiry))
        .route("/me/settings", get(my_settings).post(set_my_settings))
        .route("/accounts/{id}/approval", post(account_approval))
        .route("/accounts/{id}/dns-domain", post(account_dns_domain))
        .route("/keys", get(keys).post(create_key))
        .route("/keys/{id}/revoke", post(revoke_key))
        .route("/rules", get(rules).post(add_rule))
        .route("/rules/{id}", delete(delete_rule))
        .route("/shares", get(shares).post(create_share))
        .route("/shares/{id}", delete(end_share))
        .route("/shares/{id}/accept", post(accept_share))
        .route("/shares/{id}/ports", post(share_ports))
        .route("/shares/{id}/exit", post(share_exit))
        .route("/share-links", post(create_link))
        .route("/share-links/{id}", delete(revoke_link))
        .route("/share-links/redeem", post(redeem_link))
        .route("/accounts", get(accounts).post(create_account))
        .route("/accounts/{id}", delete(delete_account))
        .route("/accounts/{id}/status", post(account_status))
        .route("/accounts/{id}/role", post(account_role))
        .route("/accounts/{id}/password", post(account_password))
        .route("/invites", get(invites).post(create_invite))
        .route("/invites/{id}", delete(revoke_invite))
}

fn session_cookie(token: &str, tls: bool, max_age: i64) -> HeaderValue {
    let secure = if tls { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    ))
    .expect("valid cookie")
}

fn with_cookie(v: Value, token: &str, tls: bool, max_age: i64) -> Response {
    let mut r = Json(v).into_response();
    r.headers_mut()
        .insert(header::SET_COOKIE, session_cookie(token, tls, max_age));
    r
}

// ---- sign-in ----

async fn info(State(p): P) -> ApiResult {
    ok(json!({
        "signup": p.cfg.signup.as_str(),
        "domain": p.cfg.domain,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    admin_token: String,
}

fn too_many() -> ApiError {
    ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts: wait a little and try again".into(),
    )
}

async fn login(State(p): P, Extension(c): Extension<ConnInfo>, Json(b): Json<Login>) -> ApiResult {
    if !p.by_client.take(&auth::client_key(c.peer.ip())) {
        return Err(too_many());
    }
    let wrong = || ApiError(StatusCode::UNAUTHORIZED, "wrong name or password".into());
    if !b.admin_token.trim().is_empty() {
        if p.db.lock().unwrap().check_admin_token(b.admin_token.trim())? {
            let t = p.new_session(Who::Admin);
            return Ok(with_cookie(json!({ "ok": true }), &t, c.tls, SESSION_TTL));
        }
        return Err(ApiError(StatusCode::UNAUTHORIZED, "wrong admin token".into()));
    }
    let name = b.name.trim().to_ascii_lowercase();
    if !p.by_account.take(&format!("account:{name}")) {
        return Err(too_many());
    }
    let row = p.db.lock().unwrap().password_hash(&name)?;
    let hash = row.as_ref().map(|(_, h)| h.clone());
    let pw = b.password;
    let good = p.hash(move || auth::verify_password(&pw, hash.as_deref())).await;
    let Some((a, _)) = row.filter(|_| good) else {
        return Err(wrong());
    };
    match a.status {
        Status::Active => {}
        Status::Pending => return Err(ApiError::bad("your account is waiting for an operator's approval")),
        Status::Suspended => return Err(ApiError::bad("your account is suspended")),
    }
    let t = p.new_session(Who::Account(a.id));
    Ok(with_cookie(json!({ "ok": true }), &t, c.tls, SESSION_TTL))
}

async fn logout(State(p): P, Extension(c): Extension<ConnInfo>, headers: HeaderMap) -> ApiResult {
    if let Some(t) = cookie(&headers, SESSION_COOKIE) {
        p.end_session(&t);
    }
    Ok(with_cookie(json!({ "ok": true }), "", c.tls, 0))
}

#[derive(Deserialize)]
struct SignupReq {
    name: String,
    password: String,
    #[serde(default)]
    invite: String,
}

async fn signup(State(p): P, Extension(c): Extension<ConnInfo>, Json(b): Json<SignupReq>) -> ApiResult {
    let invite = Some(b.invite.trim()).filter(|i| !i.is_empty()).map(String::from);
    let status = match (p.cfg.signup, &invite) {
        (Signup::Off, _) => return Err(ApiError::bad("sign-up is turned off on this server")),
        (Signup::Invite, None) => return Err(ApiError::bad("an invite code is needed to sign up")),
        (Signup::Approval, _) => Status::Pending,
        (Signup::Invite | Signup::Open, _) => Status::Active,
    };
    if !p.by_client.take(&auth::client_key(c.peer.ip())) {
        return Err(too_many());
    }
    auth::check_password_rules(&b.password)?;
    let pw = b.password;
    let hash = p.hash(move || auth::hash_password(&pw)).await?;
    let a =
        p.db.lock()
            .unwrap()
            .sign_up(&b.name, &hash, invite.as_deref(), status)?;
    tracing::info!("portal: {} signed up ({})", a.name, a.status.as_str());
    if a.status == Status::Active {
        let t = p.new_session(Who::Account(a.id));
        return Ok(with_cookie(json!({ "status": "active" }), &t, c.tls, SESSION_TTL));
    }
    ok(json!({ "status": a.status.as_str() }))
}

/// The address machines join with: --public-url, or the host name the
/// browser used.
fn join_server(p: &Portal, headers: &HeaderMap) -> String {
    if p.cfg.public_server.is_empty() {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("SERVER");
        host.strip_suffix(":443").unwrap_or(host).to_string()
    } else {
        p.cfg.public_server.clone()
    }
}

/// What an auth key's QR code holds: a `tailconnect-ssh://join` link with
/// the hub, the key and (for a self-signed hub) its TLS fingerprint, for an
/// app that opens such links with its login filled in.
pub fn join_url(server: &str, key: &str, fingerprint: Option<&str>) -> String {
    fn pct(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    let mut u = format!("tailconnect-ssh://join?server={}&key={}", pct(server), pct(key));
    if let Some(fp) = fingerprint.filter(|f| !f.is_empty()) {
        u.push_str(&format!("&fp={}", pct(fp)));
    }
    u
}

/// `text` as a QR code in SVG: black on white with the standard quiet zone,
/// so it scans in dark mode too.
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

async fn me(State(p): P, me: Me, headers: HeaderMap) -> ApiResult {
    let server = join_server(&p, &headers);
    ok(json!({
        "name": me.account.as_ref().map(|a| a.name.clone()),
        "operator": me.operator,
        "admin_token": me.account.is_none(),
        "domain": p.cfg.domain,
        "zone": me.account.as_ref().map(|a| crate::server::db::account_zone(&a.name, a.dns_domain.as_deref(), &p.cfg.domain)),
        "signup": p.cfg.signup.as_str(),
        "server": server,
        "tls_fingerprint": p.cfg.tls_fingerprint,
    }))
}

/// A summary: the server, and counts of what `me` may see.
async fn status(State(p): P, me: Me) -> ApiResult {
    let online = (p.online)();
    let db = p.db.lock().unwrap();
    let nodes: Vec<_> = db.nodes()?.into_iter().filter(|n| me.may(n.account_id)).collect();
    let mut v = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "domain": p.cfg.domain,
        "signup": p.cfg.signup.as_str(),
        "account": me.account.as_ref().map(|a| a.name.clone()),
        "operator": me.operator,
        "machines": nodes.len(),
        "online": nodes.iter().filter(|n| online.contains(&n.ip)).count(),
        "awaiting_approval": nodes.iter().filter(|n| !n.approved).count(),
    });
    if me.operator {
        let accounts = db.accounts()?;
        v["accounts"] = json!(accounts.len());
        v["pending"] = json!(accounts.iter().filter(|a| a.status == Status::Pending).count());
    }
    ok(v)
}

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    new: String,
}

async fn change_password(
    State(p): P,
    Extension(c): Extension<ConnInfo>,
    me: Me,
    Json(b): Json<PasswordChange>,
) -> ApiResult {
    let Some(a) = me.account else {
        return Err(ApiError::bad(
            "the admin token has no password; replace it with `tc-control admin-token`",
        ));
    };
    if !p.by_client.take(&auth::client_key(c.peer.ip())) || !p.by_account.take(&format!("account:{}", a.name)) {
        return Err(too_many());
    }
    auth::check_password_rules(&b.new)?;
    let hash = p.db.lock().unwrap().password_hash(&a.name)?.map(|(_, h)| h);
    let cur = b.current;
    if !p.hash(move || auth::verify_password(&cur, hash.as_deref())).await {
        return Err(ApiError::bad("the current password is wrong"));
    }
    let new = b.new;
    let h = p.hash(move || auth::hash_password(&new)).await?;
    p.db.lock().unwrap().set_password(&a.name, Some(&h))?;
    // Every session of the account ends; this one carries on with a new one
    // (sessions created in the second of the change, or later, are valid).
    let t = p.new_session(Who::Account(a.id));
    Ok(with_cookie(json!({ "ok": true }), &t, c.tls, SESSION_TTL))
}

// ---- machines ----

/// Each account's MagicDNS zone, by account id.
fn account_zones(db: &crate::server::db::Db, domain: &str) -> anyhow::Result<std::collections::HashMap<i64, String>> {
    Ok(db
        .accounts()?
        .into_iter()
        .map(|a| {
            (
                a.id,
                crate::server::db::account_zone(&a.name, a.dns_domain.as_deref(), domain),
            )
        })
        .collect())
}

async fn machines(State(p): P, me: Me) -> ApiResult {
    let online = (p.online)();
    let traffic = (p.traffic)();
    let (nodes, zones) = {
        let db = p.db.lock().unwrap();
        (db.nodes()?, account_zones(&db, &p.cfg.domain)?)
    };
    let v: Vec<Value> = nodes
        .into_iter()
        .filter(|n| me.may(n.account_id))
        .map(|n| {
            json!({
                "id": n.id,
                "name": n.name,
                "account": n.account,
                "fqdn": format!("{}.{}", n.name, zones.get(&n.account_id).cloned().unwrap_or_default()),
                "ip": n.ip.to_string(),
                "tags": n.tags,
                "exit_node": n.exit_node,
                "expires": n.expires,
                "expired": n.expired(crate::now_unix()),
                "approved": n.approved,
                "ephemeral": n.ephemeral,
                "hostname": n.hostname,
                "online": online.contains(&n.ip),
                "traffic": traffic.get(&n.ip).map(|r| {
                    let (rx, tx, rr, tr) = r.peers.values().fold((0u64, 0u64, 0f64, 0f64), |a, v| {
                        (a.0 + v.0, a.1 + v.1, a.2 + v.2, a.3 + v.3)
                    });
                    json!({ "rx": rx, "tx": tx, "rx_rate": rr.round(), "tx_rate": tr.round(),
                            "age": r.at.elapsed().as_secs() })
                }),
                "last_seen": n.last_seen,
                "created": n.created,
            })
        })
        .collect();
    ok(json!(v))
}

/// The machine `id`, if `me` may act on it.
fn own_node(p: &Portal, me: &Me, id: i64) -> Result<crate::server::db::NodeRow, ApiError> {
    let n = p.db.lock().unwrap().node(id).map_err(|_| ApiError::not_found())?;
    if !me.may(n.account_id) {
        return Err(ApiError::not_found());
    }
    Ok(n)
}

/// A machine `me` may share: one of its own account's. Not another
/// account's, operators included (sharing what was shared with you, or a
/// tenant's machine, would hand out access its owner didn't give); only the
/// admin token, which has no account, may share any machine.
fn shareable_node(p: &Portal, me: &Me, id: i64) -> Result<crate::server::db::NodeRow, ApiError> {
    let n = own_node(p, me, id)?;
    match me.account_id() {
        Some(a) if a != n.account_id => Err(ApiError::bad(format!(
            "{}.{} belongs to account {}: only its own account can share it",
            n.name, n.account, n.account
        ))),
        _ => Ok(n),
    }
}

/// Whom one of `me`'s machines exchanges data with. Peers are named if
/// `me` may know them: operators see all; tenants see their own account's
/// machines and machines linked to theirs by a share. Others show as
/// "another machine" (a machine since removed, or a share that ended).
async fn machine_traffic(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let n = own_node(&p, &me, id)?;
    let report = (p.traffic)().remove(&n.ip);
    let Some(report) = report else {
        return ok(json!({ "machine": format!("{}.{}", n.name, n.account), "reported": false, "peers": [] }));
    };
    let db = p.db.lock().unwrap();
    let nodes: std::collections::HashMap<std::net::Ipv4Addr, crate::server::db::NodeRow> =
        db.nodes()?.into_iter().map(|x| (x.ip, x)).collect();
    let shares: Vec<(i64, i64)> = db
        .shares()?
        .into_iter()
        .filter(|s| s.accepted)
        .map(|s| (s.node_id, s.account_id))
        .collect();
    drop(db);
    let named = |peer: &crate::server::db::NodeRow| {
        me.operator
            || peer.account_id == n.account_id
            || shares.contains(&(peer.id, n.account_id))
            || shares.contains(&(n.id, peer.account_id))
    };
    let mut peers: Vec<(String, Value)> = report
        .peers
        .iter()
        .map(|(ip, (rx, tx, rr, tr))| {
            let (name, addr) = match nodes.get(ip).filter(|x| named(x)) {
                Some(x) => (format!("{}.{}", x.name, x.account), Some(ip.to_string())),
                None => ("another machine".to_string(), None),
            };
            let v =
                json!({ "peer": name, "ip": addr, "rx": rx, "tx": tx, "rx_rate": rr.round(), "tx_rate": tr.round() });
            (name, v)
        })
        .collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    ok(json!({
        "machine": format!("{}.{}", n.name, n.account),
        "reported": true,
        "age": report.at.elapsed().as_secs(),
        "peers": peers.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct Tags {
    tags: String,
}

async fn tag_machine(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<Tags>) -> ApiResult {
    own_node(&p, &me, id)?;
    let tags: Vec<String> = b.tags.split(',').map(String::from).collect();
    let set = p.db.lock().unwrap().set_tags(id, &tags)?;
    ok(json!({ "tags": set }))
}

#[derive(Deserialize)]
struct Name {
    name: String,
}

#[derive(Deserialize)]
struct Enabled {
    enabled: bool,
}

/// Let a machine that waits for its account's approval join.
async fn approve_machine(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    own_node(&p, &me, id)?;
    p.db.lock().unwrap().approve_node(id)?;
    ok(json!({ "approved": true }))
}

#[derive(Deserialize)]
struct Expiry {
    /// `never`, `default` (the hub's key lifetime from now) or a duration
    /// from now (`90d`, `12h`).
    expiry: String,
}

async fn machine_expiry(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<Expiry>) -> ApiResult {
    own_node(&p, &me, id)?;
    let now = crate::now_unix();
    let db = p.db.lock().unwrap();
    let e = match b.expiry.trim() {
        "never" => None,
        "default" => db.hub_key_expiry().map(|e| now + e),
        d => Some(now + crate::server::parse_duration(d)?),
    };
    db.set_node_expiry(id, e)?;
    ok(json!({ "expires": e }))
}

async fn my_settings(State(p): P, me: Me) -> ApiResult {
    let Some(a) = me.account else {
        return Err(ApiError::bad("the admin token has no account"));
    };
    ok(settings_json(&p, &a))
}

fn settings_json(p: &Portal, a: &crate::server::db::AccountRow) -> Value {
    json!({
        "require_approval": a.require_approval,
        "dns_domain": a.dns_domain,
        "zone": crate::server::db::account_zone(&a.name, a.dns_domain.as_deref(), &p.cfg.domain),
        "default_zone": format!("{}.{}", a.name, p.cfg.domain),
        "allowed_suffixes": p.cfg.tenant_domain_suffixes,
    })
}

#[derive(Deserialize)]
struct Settings {
    #[serde(default)]
    require_approval: Option<bool>,
    /// The account's own MagicDNS domain; "" for the default.
    #[serde(default)]
    dns_domain: Option<String>,
}

/// An account's own settings: whether new machines need approval.
async fn set_my_settings(State(p): P, me: Me, Json(b): Json<Settings>) -> ApiResult {
    let Some(a) = me.account else {
        return Err(ApiError::bad("the admin token has no account"));
    };
    if let Some(r) = b.require_approval {
        p.db.lock().unwrap().set_require_approval(&a.name, r)?;
    }
    if let Some(d) = &b.dns_domain {
        // Tenants choose within the allowed suffixes; operators may set any.
        let suffixes = (!me.operator).then_some(p.cfg.tenant_domain_suffixes.as_slice());
        p.db.lock()
            .unwrap()
            .set_dns_domain(&a.name, Some(d), &p.cfg.domain, suffixes)?;
    }
    let a = p.db.lock().unwrap().account(&a.name)?;
    ok(settings_json(&p, &a))
}

#[derive(Deserialize)]
struct Domain {
    domain: String,
}

/// An operator sets an account's MagicDNS domain (any domain; "" for the default).
async fn account_dns_domain(State(p): P, _op: Op, Path(id): Path<i64>, Json(b): Json<Domain>) -> ApiResult {
    let name = account_name(&p, id)?;
    let d =
        p.db.lock()
            .unwrap()
            .set_dns_domain(&name, Some(&b.domain), &p.cfg.domain, None)?;
    ok(json!({ "dns_domain": d, "zone": crate::server::db::account_zone(&name, d.as_deref(), &p.cfg.domain) }))
}

async fn account_approval(State(p): P, _op: Op, Path(id): Path<i64>, Json(b): Json<Enabled>) -> ApiResult {
    let name = account_name(&p, id)?;
    p.db.lock().unwrap().set_require_approval(&name, b.enabled)?;
    ok(json!({ "require_approval": b.enabled }))
}

/// Let a machine route internet traffic for its account's machines, or stop.
async fn exit_node(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<Enabled>) -> ApiResult {
    own_node(&p, &me, id)?;
    p.db.lock().unwrap().set_exit_node(id, b.enabled)?;
    ok(json!({ "exit_node": b.enabled }))
}

async fn rename_machine(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<Name>) -> ApiResult {
    own_node(&p, &me, id)?;
    let n = p.db.lock().unwrap().rename_node(id, &b.name)?;
    ok(json!({ "name": n }))
}

async fn remove_machine(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    own_node(&p, &me, id)?;
    p.db.lock().unwrap().remove_node(id)?;
    ok(json!({ "ok": true }))
}

// ---- auth keys ----

/// The account a tenant acts for, or the one an operator picked.
fn target_account(p: &Portal, me: &Me, given: Option<&str>) -> Result<crate::server::db::AccountRow, ApiError> {
    match (given.map(str::trim).filter(|s| !s.is_empty()), &me.account) {
        (Some(name), _) if me.operator => p.db.lock().unwrap().account(name).map_err(|_| ApiError::not_found()),
        (Some(name), Some(a)) if a.name == name => Ok(a.clone()),
        (Some(_), _) => Err(ApiError::not_found()),
        (None, Some(a)) => Ok(a.clone()),
        (None, None) => Err(ApiError::bad("choose an account")),
    }
}

async fn keys(State(p): P, me: Me) -> ApiResult {
    let db = p.db.lock().unwrap();
    let accounts: std::collections::HashMap<String, i64> = db.accounts()?.into_iter().map(|a| (a.name, a.id)).collect();
    let now = now_unix();
    let v: Vec<Value> = db
        .authkeys()?
        .into_iter()
        .filter(|k| accounts.get(&k.account).is_some_and(|id| me.may(*id)))
        .map(|k| {
            let state = if k.revoked {
                "revoked"
            } else if k.expires.is_some_and(|e| e <= now) {
                "expired"
            } else if !k.reusable && k.used > 0 {
                "used"
            } else {
                "active"
            };
            json!({
                "id": k.id, "account": k.account, "prefix": k.prefix, "reusable": k.reusable,
                "expires": k.expires, "used": k.used, "state": state, "created": k.created,
                "ephemeral": k.ephemeral, "preapproved": k.preapproved,
            })
        })
        .collect();
    ok(json!(v))
}

#[derive(Deserialize)]
struct NewKey {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    reusable: bool,
    expires_hours: u32,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    preapproved: bool,
}

async fn create_key(State(p): P, me: Me, headers: HeaderMap, Json(b): Json<NewKey>) -> ApiResult {
    if !(1..=24 * 365).contains(&b.expires_hours) {
        return Err(ApiError::bad("keys expire after 1 hour to 1 year"));
    }
    let a = target_account(&p, &me, b.account.as_deref())?;
    let exp = now_unix() + b.expires_hours as i64 * 3600;
    let key =
        p.db.lock()
            .unwrap()
            .create_authkey_with(&a.name, b.reusable, Some(exp), b.ephemeral, b.preapproved)?;
    let link = join_url(&join_server(&p, &headers), &key, p.cfg.tls_fingerprint.as_deref());
    ok(json!({ "key": key, "account": a.name, "join_url": link, "qr_svg": qr_svg(&link) }))
}

async fn revoke_key(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let k = db
        .authkeys()?
        .into_iter()
        .find(|k| k.id == id)
        .ok_or_else(ApiError::not_found)?;
    let a = db.account(&k.account)?;
    if !me.may(a.id) {
        return Err(ApiError::not_found());
    }
    db.revoke_authkey(id)?;
    ok(json!({ "ok": true }))
}

// ---- access rules ----

#[derive(Deserialize)]
struct AccountQuery {
    #[serde(default)]
    account: Option<String>,
}

async fn rules(State(p): P, me: Me, Query(q): Query<AccountQuery>) -> ApiResult {
    let a = target_account(&p, &me, q.account.as_deref())?;
    let v: Vec<Value> =
        p.db.lock()
            .unwrap()
            .rules()?
            .into_iter()
            .filter(|r| r.account_id == a.id)
            .map(|r| json!({ "id": r.id, "account": r.account, "from": r.src, "to": r.dst, "ports": r.ports }))
            .collect();
    ok(json!({ "account": a.name, "rules": v }))
}

#[derive(Deserialize)]
struct NewRule {
    #[serde(default)]
    account: Option<String>,
    from: String,
    to: String,
    ports: String,
}

async fn add_rule(State(p): P, me: Me, Json(b): Json<NewRule>) -> ApiResult {
    let a = target_account(&p, &me, b.account.as_deref())?;
    let ports = if b.ports.trim().is_empty() {
        "*"
    } else {
        b.ports.as_str()
    };
    let id = p.db.lock().unwrap().add_rule(&a.name, &b.from, &b.to, ports)?;
    ok(json!({ "id": id }))
}

async fn delete_rule(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let r = db
        .rules()?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(ApiError::not_found)?;
    if !me.may(r.account_id) {
        return Err(ApiError::not_found());
    }
    db.delete_rule(id)?;
    ok(json!({ "ok": true }))
}

// ---- sharing ----

async fn shares(State(p): P, me: Me) -> ApiResult {
    let db = p.db.lock().unwrap();
    let mine = me.account_id();
    let row = |s: &crate::server::db::ShareRow| {
        json!({
            "id": s.id, "node_id": s.node_id, "machine": format!("{}.{}", s.node, s.owner),
            "owner": s.owner, "account": s.account, "ports": s.ports, "exit": s.exit,
            "status": if s.accepted { "active" } else { "pending" }, "created": s.created,
        })
    };
    let all = db.shares()?;
    let by_me: Vec<Value> = all.iter().filter(|s| me.may(s.owner_id)).map(row).collect();
    let with_me: Vec<Value> = all.iter().filter(|s| Some(s.account_id) == mine).map(row).collect();
    let now = now_unix();
    let links: Vec<Value> = db
        .share_links()?
        .into_iter()
        .filter(|l| me.may(l.owner_id))
        .map(|l| {
            let state = match (&l.used_by, l.revoked, l.expires <= now) {
                (Some(_), _, _) => "used",
                (None, true, _) => "revoked",
                (None, false, true) => "expired",
                _ => "unused",
            };
            json!({
                "id": l.id, "prefix": l.prefix, "machine": format!("{}.{}", l.node, l.owner),
                "ports": l.ports, "expires": l.expires, "used_by": l.used_by, "state": state,
            })
        })
        .collect();
    ok(json!({ "by_me": by_me, "with_me": with_me, "links": links }))
}

#[derive(Deserialize)]
struct NewShare {
    node_id: i64,
    account: String,
    #[serde(default)]
    ports: String,
    /// Also share it as an exit node.
    #[serde(default)]
    exit: bool,
}

fn ports_or_all(s: &str) -> &str {
    if s.trim().is_empty() { "*" } else { s }
}

async fn create_share(State(p): P, me: Me, Json(b): Json<NewShare>) -> ApiResult {
    shareable_node(&p, &me, b.node_id)?;
    let db = p.db.lock().unwrap();
    // Don't reveal whether an account exists beyond what the share needs:
    // sharing with a name that doesn't exist fails the same way as a typo.
    let id = db.create_share(b.node_id, b.account.trim(), ports_or_all(&b.ports))?;
    if b.exit {
        db.set_share_exit(id, true)?;
    }
    ok(json!({ "id": id }))
}

async fn accept_share(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let s = db.share(id).map_err(|_| ApiError::not_found())?;
    if Some(s.account_id) != me.account_id() && !me.operator {
        return Err(ApiError::not_found());
    }
    db.accept_share(id)?;
    ok(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct Ports {
    ports: String,
}

async fn share_ports(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<Ports>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let s = db.share(id).map_err(|_| ApiError::not_found())?;
    if !me.may(s.owner_id) {
        return Err(ApiError::not_found());
    }
    let ports = db.set_share_ports(id, ports_or_all(&b.ports))?;
    ok(json!({ "ports": ports }))
}

#[derive(Deserialize)]
struct On {
    on: bool,
}

/// The owner lets the share's account use the machine as its exit node, or not.
async fn share_exit(State(p): P, me: Me, Path(id): Path<i64>, Json(b): Json<On>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let s = db.share(id).map_err(|_| ApiError::not_found())?;
    if !me.may(s.owner_id) {
        return Err(ApiError::not_found());
    }
    db.set_share_exit(id, b.on)?;
    ok(json!({ "exit": b.on }))
}

/// The owner revokes, or the recipient removes or declines.
async fn end_share(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let s = db.share(id).map_err(|_| ApiError::not_found())?;
    if !me.may(s.owner_id) && Some(s.account_id) != me.account_id() {
        return Err(ApiError::not_found());
    }
    db.revoke_share(id)?;
    ok(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct NewLink {
    node_id: i64,
    #[serde(default)]
    ports: String,
    days: u32,
}

async fn create_link(State(p): P, me: Me, Json(b): Json<NewLink>) -> ApiResult {
    if !(1..=90).contains(&b.days) {
        return Err(ApiError::bad("links are valid for 1 to 90 days"));
    }
    shareable_node(&p, &me, b.node_id)?;
    let exp = now_unix() + b.days as i64 * 86400;
    let code =
        p.db.lock()
            .unwrap()
            .create_share_link(b.node_id, ports_or_all(&b.ports), exp)?;
    ok(json!({ "code": code }))
}

async fn revoke_link(State(p): P, me: Me, Path(id): Path<i64>) -> ApiResult {
    let db = p.db.lock().unwrap();
    let l = db
        .share_links()?
        .into_iter()
        .find(|l| l.id == id)
        .ok_or_else(ApiError::not_found)?;
    if !me.may(l.owner_id) {
        return Err(ApiError::not_found());
    }
    db.revoke_share_link(id)?;
    ok(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

async fn redeem_link(State(p): P, Extension(c): Extension<ConnInfo>, me: Me, Json(b): Json<Code>) -> ApiResult {
    let Some(a) = me.account_id() else {
        return Err(ApiError::bad("sign in with an account to add a shared machine"));
    };
    if !p.by_client.take(&auth::client_key(c.peer.ip())) {
        return Err(too_many());
    }
    let id = p.db.lock().unwrap().redeem_share_link(b.code.trim(), a)?;
    ok(json!({ "id": id }))
}

// ---- accounts and invites (operators) ----

async fn accounts(State(p): P, _op: Op) -> ApiResult {
    let db = p.db.lock().unwrap();
    let nodes = db.nodes()?;
    let v: Vec<Value> = db
        .accounts()?
        .into_iter()
        .map(|a| {
            json!({
                "id": a.id, "name": a.name, "status": a.status.as_str(), "role": a.role.as_str(),
                "has_password": a.has_password,
                "require_approval": a.require_approval,
                "dns_domain": a.dns_domain,
                "machines": nodes.iter().filter(|n| n.account_id == a.id).count(),
                "created": a.created,
            })
        })
        .collect();
    ok(json!(v))
}

#[derive(Deserialize)]
struct NewAccount {
    name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    operator: bool,
}

async fn create_account(State(p): P, _op: Op, Json(b): Json<NewAccount>) -> ApiResult {
    let hash = if b.password.is_empty() {
        None
    } else {
        let pw = b.password;
        Some(p.hash(move || auth::hash_password(&pw)).await?)
    };
    let role = if b.operator { Role::Operator } else { Role::Tenant };
    let a =
        p.db.lock()
            .unwrap()
            .create_account_with(&b.name, Status::Active, role, hash.as_deref())?;
    ok(json!({ "id": a.id, "name": a.name }))
}

fn account_name(p: &Portal, id: i64) -> Result<String, ApiError> {
    Ok(p.db
        .lock()
        .unwrap()
        .account_by_id(id)
        .map_err(|_| ApiError::not_found())?
        .name)
}

#[derive(Deserialize)]
struct NewStatus {
    status: String,
}

async fn account_status(State(p): P, Op(me): Op, Path(id): Path<i64>, Json(b): Json<NewStatus>) -> ApiResult {
    let status = match b.status.as_str() {
        "active" => Status::Active,
        "suspended" => Status::Suspended,
        _ => return Err(ApiError::bad("status must be active or suspended")),
    };
    if me.account_id() == Some(id) && status != Status::Active {
        return Err(ApiError::bad("you can't suspend your own account"));
    }
    let name = account_name(&p, id)?;
    p.db.lock().unwrap().set_account_status(&name, status)?;
    ok(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct NewRole {
    role: String,
}

async fn account_role(State(p): P, Op(me): Op, Path(id): Path<i64>, Json(b): Json<NewRole>) -> ApiResult {
    let role = Role::parse(&b.role)?;
    if me.account_id() == Some(id) && role != Role::Operator {
        return Err(ApiError::bad("you can't remove your own operator role"));
    }
    let name = account_name(&p, id)?;
    p.db.lock().unwrap().set_role(&name, role)?;
    ok(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct NewPassword {
    password: String,
}

async fn account_password(State(p): P, _op: Op, Path(id): Path<i64>, Json(b): Json<NewPassword>) -> ApiResult {
    let name = account_name(&p, id)?;
    let pw = b.password;
    let h = p.hash(move || auth::hash_password(&pw)).await?;
    p.db.lock().unwrap().set_password(&name, Some(&h))?;
    ok(json!({ "ok": true }))
}

async fn delete_account(State(p): P, Op(me): Op, Path(id): Path<i64>) -> ApiResult {
    if me.account_id() == Some(id) {
        return Err(ApiError::bad("you can't delete your own account"));
    }
    let name = account_name(&p, id)?;
    p.db.lock().unwrap().delete_account(&name)?;
    ok(json!({ "ok": true }))
}

async fn invites(State(p): P, _op: Op) -> ApiResult {
    let now = now_unix();
    let v: Vec<Value> =
        p.db.lock()
            .unwrap()
            .invites()?
            .into_iter()
            .map(|i| {
                let state = match (&i.used_by, i.revoked, i.expires <= now) {
                    (Some(_), _, _) => "used",
                    (None, true, _) => "revoked",
                    (None, false, true) => "expired",
                    _ => "unused",
                };
                json!({ "id": i.id, "prefix": i.prefix, "expires": i.expires, "used_by": i.used_by,
                    "state": state, "created": i.created })
            })
            .collect();
    ok(json!(v))
}

#[derive(Deserialize)]
struct NewInvite {
    days: u32,
}

async fn create_invite(State(p): P, _op: Op, Json(b): Json<NewInvite>) -> ApiResult {
    if !(1..=90).contains(&b.days) {
        return Err(ApiError::bad("invites are valid for 1 to 90 days"));
    }
    let code = p.db.lock().unwrap().create_invite(now_unix() + b.days as i64 * 86400)?;
    ok(json!({ "code": code }))
}

async fn revoke_invite(State(p): P, _op: Op, Path(id): Path<i64>) -> ApiResult {
    p.db.lock().unwrap().revoke_invite(id)?;
    ok(json!({ "ok": true }))
}
