//! The web portal: a JSON API and a single-page UI, served on the hub's TLS
//! port. Browsers negotiate HTTP/1.1 by ALPN; `tcd` negotiates `tc-ssh/1`
//! on the same port and gets SSH.
//!
//! Security:
//! * sessions are random tokens kept in memory (only their hashes), in an
//!   `HttpOnly`, `SameSite=Strict` cookie, valid for 12 hours; a password,
//!   role or status change ends the account's sessions, even when made with
//!   the CLI, and replacing the admin token ends token sessions;
//! * writes are accepted only as JSON from the portal's own origin, or with
//!   the admin token as a bearer token (scripts, see docs/api.md);
//! * the portal answers only to host names it knows (DNS rebinding);
//! * a strict Content Security Policy, and the UI builds pages from text,
//!   never from HTML;
//! * password guesses are limited per client and per account, take the same
//!   time whether or not the account exists, and at most four hashes are
//!   computed at once.

mod api;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

use super::auth::Limiter;
use super::db::{AccountRow, Db, Role, Status};
use crate::now_unix;

const SESSION_COOKIE: &str = "tc_session";
const SESSION_TTL: i64 = 12 * 3600;

/// Who may create accounts in the portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signup {
    Off,
    /// New accounts wait for an operator's approval.
    Approval,
    /// An invite code is required.
    Invite,
    /// Anyone who can reach the portal.
    Open,
}

impl Signup {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "off" => Signup::Off,
            "approval" => Signup::Approval,
            "invite" => Signup::Invite,
            "open" => Signup::Open,
            _ => anyhow::bail!("--signup must be off, approval, invite or open"),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Signup::Off => "off",
            Signup::Approval => "approval",
            Signup::Invite => "invite",
            Signup::Open => "open",
        }
    }
}

pub struct Config {
    pub signup: Signup,
    pub domain: String,
    /// What `tc up --server` should say. Empty: the host name the browser used.
    pub public_server: String,
    /// The certificate's fingerprint, when clients must pin it.
    pub tls_fingerprint: Option<String>,
    /// Host names the portal answers to, besides IP addresses and `localhost`.
    pub hosts: Vec<String>,
    /// Domains tenants may choose for their account end in one of these.
    pub tenant_domain_suffixes: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
enum Who {
    Account(i64),
    /// Signed in with the admin token: an operator without an account.
    Admin,
}

#[derive(Clone, Copy, Debug)]
struct Session {
    who: Who,
    created: i64,
}

/// Addresses with a session to the hub right now.
pub type OnlineFn = Arc<dyn Fn() -> HashSet<Ipv4Addr> + Send + Sync>;

/// The machines' latest traffic reports, by address.
pub type TrafficFn = Arc<dyn Fn() -> HashMap<Ipv4Addr, crate::server::TrafficReport> + Send + Sync>;

pub struct Portal {
    cfg: Config,
    db: Mutex<Db>,
    sessions: Mutex<HashMap<String, Session>>,
    by_client: Limiter,
    by_account: Limiter,
    hashing: Semaphore,
    online: OnlineFn,
    traffic: TrafficFn,
}

/// The connection a request arrived on.
#[derive(Clone, Copy, Debug)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    pub tls: bool,
}

/// The signed-in user of a request.
#[derive(Debug, Clone)]
pub struct Me {
    /// `None` for an admin-token session.
    pub account: Option<AccountRow>,
    pub operator: bool,
}

impl Me {
    pub fn account_id(&self) -> Option<i64> {
        self.account.as_ref().map(|a| a.id)
    }

    /// May act on objects of account `id`?
    pub fn may(&self, id: i64) -> bool {
        self.operator || self.account_id() == Some(id)
    }
}

fn hash_token(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

impl Portal {
    pub fn new(cfg: Config, db: Db, online: OnlineFn, traffic: TrafficFn) -> Arc<Self> {
        Arc::new(Portal {
            cfg,
            db: Mutex::new(db),
            sessions: Mutex::new(HashMap::new()),
            by_client: Limiter::new(10, Duration::from_secs(6)),
            by_account: Limiter::new(20, Duration::from_secs(60)),
            hashing: Semaphore::new(4),
            online,
            traffic,
        })
    }

    fn new_session(&self, who: Who) -> String {
        let token = hex::encode(rand::random::<[u8; 32]>());
        let mut s = self.sessions.lock().unwrap();
        let now = now_unix();
        s.retain(|_, v| now - v.created < SESSION_TTL);
        s.insert(hash_token(&token), Session { who, created: now });
        token
    }

    fn end_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(&hash_token(token));
    }

    /// The user a session token stands for, if it's still valid.
    fn resolve(&self, token: &str) -> Option<Me> {
        let s = *self.sessions.lock().unwrap().get(&hash_token(token))?;
        if now_unix() - s.created >= SESSION_TTL {
            self.end_session(token);
            return None;
        }
        let db = self.db.lock().unwrap();
        let me = match s.who {
            Who::Admin => {
                if db.admin_token_changed().ok()? > s.created {
                    None
                } else {
                    Some(Me {
                        account: None,
                        operator: true,
                    })
                }
            }
            Who::Account(id) => {
                let a = db.account_by_id(id).ok()?;
                let valid = a.status == Status::Active && a.has_password && a.changed <= s.created;
                valid.then(|| Me {
                    operator: a.role == Role::Operator,
                    account: Some(a),
                })
            }
        };
        drop(db);
        if me.is_none() {
            self.end_session(token);
        }
        me
    }

    /// Run `f` (a password hash or check) off the runtime, at most four at once.
    async fn hash<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> T {
        let _permit = self.hashing.acquire().await.expect("semaphore open");
        tokio::task::spawn_blocking(f).await.expect("hashing task")
    }

    fn host_allowed(&self, host: &str) -> bool {
        let h = strip_port(host).to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        h.parse::<IpAddr>().is_ok() || h == "localhost" || self.cfg.hosts.iter().any(|x| x == h)
    }
}

/// `host:port`, `[v6]:port` or `host` → the host part.
fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((a, p)) if !a.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => a,
        _ => h,
    }
}

/// The token of an `Authorization: Bearer TOKEN` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn plain(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Host check, same-origin JSON writes, security headers.
async fn guard(State(p): State<Arc<Portal>>, req: Request, next: Next) -> Response {
    let tls = req.extensions().get::<ConnInfo>().is_some_and(|c| c.tls);
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or("")
        .to_string();
    let mut resp = if !p.host_allowed(&host) {
        plain(
            StatusCode::MISDIRECTED_REQUEST,
            "unknown host name: open the portal by the server's address or a name given with --portal-host",
        )
    } else if !matches!(*req.method(), Method::GET | Method::HEAD)
        && bearer(req.headers()).is_none()
        && !same_origin_json(req.headers(), &host, tls)
    {
        // Requests with a bearer token can't be forged by another site:
        // browsers never add Authorization by themselves, and a page can't
        // add it cross-origin without a CORS preflight, which we never
        // answer. The token itself is checked by the handler.
        plain(StatusCode::FORBIDDEN, "cross-site or non-JSON request refused")
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if tls {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

fn same_origin_json(h: &HeaderMap, host: &str, tls: bool) -> bool {
    let json = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });
    if !json {
        return false;
    }
    if let Some(site) = h.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && site != "same-origin"
        && site != "none"
    {
        return false;
    }
    match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => {
            let scheme = if tls { "https" } else { "http" };
            o.eq_ignore_ascii_case(&format!("{scheme}://{host}"))
        }
    }
}

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const APP_CSS: &str = include_str!("static/app.css");

fn asset(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}

pub fn router(p: Arc<Portal>) -> Router {
    Router::new()
        .route(
            "/",
            axum::routing::get(|| async { asset("text/html; charset=utf-8", INDEX_HTML) }),
        )
        .route(
            "/app.js",
            axum::routing::get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/app.css",
            axum::routing::get(|| async { asset("text/css; charset=utf-8", APP_CSS) }),
        )
        // `/api/v1` is the stable path for scripts; the UI uses `/api`.
        .nest("/api/v1", api::routes())
        .nest("/api", api::routes())
        .fallback(|| async { plain(StatusCode::NOT_FOUND, "not found") })
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn_with_state(p.clone(), guard))
        .with_state(p)
}

/// Serve HTTP/1.1 on one accepted connection.
pub async fn serve_conn<S>(router: Router, stream: S, info: ConnInfo)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper_util::service::TowerToHyperService::new(router.layer(axum::Extension(info)));
    let r = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(20))
        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
        .await;
    if let Err(e) = r {
        tracing::debug!("portal {}: {e}", info.peer);
    }
}

#[cfg(test)]
mod tests;
