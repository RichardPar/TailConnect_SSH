//! Built-in Let's Encrypt (ACME): the hub gets its own certificate and
//! renews it, with nothing else to install.
//!
//! Three ways to prove the name is ours:
//! * **TLS-ALPN-01** (the default) on the hub's own TLS port, which must be
//!   reachable as port 443: Let's Encrypt connects asking for ALPN
//!   `acme-tls/1`, and [`CertStore`] answers with a challenge certificate.
//! * **HTTP-01** on a separate port-80 listener (`--acme-http-listen`), when
//!   the hub's TLS port isn't 443. It redirects everything else to HTTPS.
//! * **DNS-01 through DuckDNS** (`--acme-dns duckdns`): the TXT record is set
//!   with DuckDNS's API, so nothing has to be reachable from outside.
//!
//! Until the first certificate arrives, the hub serves its self-signed one.
//! Certificates are renewed after two thirds of their lifetime (30 days before
//! expiry for 90-day certificates) and swapped in without a restart. Failures
//! are retried after 2 minutes, 10 minutes, an hour, then every 6 hours.
//!
//! Storage, in `acme/` in the state directory: the ACME account
//! (`account-LABEL.json`) and the certificate with its key
//! (`LABEL-NAME/{cert,key}.pem`), where LABEL is `letsencrypt`, `staging` or
//! `acme-HASH` for another ACME server, so test and real certificates never
//! mix.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::now_unix;

/// ALPN protocol of TLS-ALPN-01 validation connections (RFC 8737).
pub const ALPN_ACME: &[u8] = b"acme-tls/1";
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone)]
pub enum Method {
    TlsAlpn,
    Http(SocketAddr),
    DuckDns { token: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Names to get the certificate for (lower case).
    pub domains: Vec<String>,
    pub email: Option<String>,
    /// ACME directory URL.
    pub directory: String,
    /// PEM root to trust for the ACME server's own HTTPS (test servers).
    pub ca_root: Option<PathBuf>,
    pub method: Method,
    /// Where accounts and certificates are kept.
    pub dir: PathBuf,
}

impl Config {
    /// Short name of the ACME server, for file names.
    fn label(&self) -> String {
        match self.directory.as_str() {
            LETS_ENCRYPT => "letsencrypt".into(),
            LETS_ENCRYPT_STAGING => "staging".into(),
            d => format!("acme-{}", &hex::encode(Sha256::digest(d.as_bytes()))[..8]),
        }
    }

    fn cert_dir(&self) -> PathBuf {
        self.dir.join(format!("{}-{}", self.label(), self.domains[0]))
    }

    fn account_file(&self) -> PathBuf {
        self.dir.join(format!("account-{}.json", self.label()))
    }
}

/// Check and normalise `--acme-domain` names.
pub fn parse_domains(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for d in s
        .split(',')
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
    {
        if d.is_empty() {
            continue;
        }
        let ok = d.len() <= 253
            && d.contains('.')
            && d.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && !l.starts_with('-')
                    && !l.ends_with('-')
            })
            && d.parse::<std::net::IpAddr>().is_err();
        if !ok {
            bail!("--acme-domain: {d:?} isn't a DNS name (Let's Encrypt issues certificates for names, not addresses)");
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        bail!("--acme-domain is empty");
    }
    Ok(out)
}

/// The certificates the hub's TLS listener serves: the current certificate,
/// and TLS-ALPN-01 challenge certificates while a validation is running.
#[derive(Debug)]
pub struct CertStore {
    current: RwLock<Arc<CertifiedKey>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    http_tokens: RwLock<HashMap<String, String>>,
}

impl CertStore {
    pub fn new(initial: Arc<CertifiedKey>) -> Arc<Self> {
        Arc::new(CertStore {
            current: RwLock::new(initial),
            challenges: RwLock::new(HashMap::new()),
            http_tokens: RwLock::new(HashMap::new()),
        })
    }

    pub fn set(&self, ck: Arc<CertifiedKey>) {
        *self.current.write().unwrap() = ck;
    }

    /// The key authorization for an HTTP-01 token, if a validation is running.
    pub fn http_token(&self, token: &str) -> Option<String> {
        self.http_tokens.read().unwrap().get(token).cloned()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello.alpn().is_some_and(|mut a| a.any(|p| p == ALPN_ACME));
        if acme {
            // Only validation connections get challenge certificates, and only
            // for names being validated right now.
            let name = hello.server_name()?.to_ascii_lowercase();
            return self.challenges.read().unwrap().get(&name).cloned();
        }
        Some(self.current.read().unwrap().clone())
    }
}

/// A rustls certificate from a PEM chain and key.
pub fn certified_key(chain_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>> {
    let certs = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificate")?;
    if certs.is_empty() {
        bail!("no certificate in PEM");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("parsing private key")?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| anyhow!("private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

/// A TLS-ALPN-01 challenge certificate for `domain` (RFC 8737): self-signed,
/// with the key authorization's SHA-256 in the acmeIdentifier extension.
fn challenge_cert(domain: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    certified_key(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
}

/// Validity of the first certificate in a PEM chain, as Unix times, and its DNS names.
fn cert_info(chain_pem: &[u8]) -> Result<(i64, i64, Vec<String>)> {
    let der = CertificateDer::pem_slice_iter(chain_pem)
        .next()
        .context("no certificate")?
        .context("bad PEM")?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow!("parsing certificate: {e}"))?;
    let v = cert.validity();
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    x509_parser::extensions::GeneralName::DNSName(n) => Some(n.to_ascii_lowercase()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok((v.not_before.timestamp(), v.not_after.timestamp(), names))
}

/// When a certificate valid from `nb` to `na` should be renewed: after two
/// thirds of its lifetime.
fn renew_at(nb: i64, na: i64) -> i64 {
    nb + (na - nb) * 2 / 3
}

/// Delays between failed attempts.
const BACKOFF: [u64; 4] = [120, 600, 3600, 6 * 3600];

/// The saved certificate, if it covers our names: (key, renew at, expires).
fn load_saved(cfg: &Config) -> Option<(Arc<CertifiedKey>, i64, i64)> {
    let dir = cfg.cert_dir();
    let chain = std::fs::read(dir.join("cert.pem")).ok()?;
    let key = std::fs::read(dir.join("key.pem")).ok()?;
    let (nb, na, names) = cert_info(&chain).ok()?;
    if !cfg.domains.iter().all(|d| names.contains(d)) {
        info!(
            "acme: the saved certificate is for {names:?}, not {:?}: getting a new one",
            cfg.domains
        );
        return None;
    }
    let ck = certified_key(&chain, &key).ok()?;
    Some((ck, renew_at(nb, na), na))
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = crate::private_file(std::fs::OpenOptions::new().write(true).create(true).truncate(true)).open(&tmp)?;
    f.write_all(data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn fmt_time(t: i64) -> String {
    let d = t - now_unix();
    let a = d.unsigned_abs();
    let span = match a {
        0..120 => format!("{a} seconds"),
        120..7200 => format!("{} minutes", a / 60),
        7200..172800 => format!("{} hours", a / 3600),
        _ => format!("{} days", a / 86400),
    };
    if d >= 0 {
        format!("in {span}")
    } else {
        format!("{span} ago")
    }
}

/// Keep a valid certificate in `store`: load the saved one, get one when
/// there is none, and renew it in time. Runs forever.
pub async fn run(cfg: Arc<Config>, store: Arc<CertStore>) {
    if let Err(e) = std::fs::create_dir_all(&cfg.dir) {
        warn!("acme: creating {}: {e}", cfg.dir.display());
    }
    let mut failures = 0usize;
    loop {
        let due = match load_saved(&cfg) {
            Some((ck, renew, expires)) => {
                store.set(ck);
                if failures == 0 {
                    info!(
                        "acme: certificate for {} expires {}, renewal {}",
                        cfg.domains.join(", "),
                        fmt_time(expires),
                        fmt_time(renew)
                    );
                }
                renew
            }
            None => 0,
        };
        let wait = due - now_unix();
        if wait > 0 {
            // Wake at least twice a day, in case the clock jumped.
            tokio::time::sleep(Duration::from_secs(wait.min(12 * 3600) as u64)).await;
            failures = 0;
            continue;
        }
        info!(
            "acme: getting a certificate for {} from {}",
            cfg.domains.join(", "),
            cfg.directory
        );
        match issue(&cfg, &store).await {
            Ok(()) => {
                failures = 0;
                info!("acme: got a certificate for {}", cfg.domains.join(", "));
            }
            Err(e) => {
                let delay = BACKOFF[failures.min(BACKOFF.len() - 1)];
                warn!(
                    "acme: getting a certificate failed: {e:#}; trying again in {}",
                    human(delay)
                );
                failures += 1;
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

fn human(s: u64) -> String {
    if s < 3600 {
        format!("{} minutes", s / 60)
    } else {
        format!("{} hours", s / 3600)
    }
}

async fn account(cfg: &Config) -> Result<Account> {
    let builder = || match &cfg.ca_root {
        Some(p) => Account::builder_with_root(p),
        None => Account::builder(),
    };
    let path = cfg.account_file();
    if let Ok(text) = std::fs::read(&path) {
        let creds: AccountCredentials = serde_json::from_slice(&text).context("reading the ACME account")?;
        return Ok(builder()?.from_credentials(creds).await?);
    }
    let contact: Vec<String> = cfg.email.iter().map(|e| format!("mailto:{e}")).collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (acct, creds) = builder()?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.directory.clone(),
            None,
        )
        .await
        .context("creating the ACME account")?;
    write_private(&path, &serde_json::to_vec_pretty(&creds)?)?;
    info!("acme: created an account with {}", cfg.directory);
    Ok(acct)
}

/// What to undo once a validation is over.
#[derive(Default)]
struct Cleanup {
    alpn: Vec<String>,
    tokens: Vec<String>,
    duckdns: bool,
}

async fn issue(cfg: &Config, store: &CertStore) -> Result<()> {
    let mut cleanup = Cleanup::default();
    let r = issue_inner(cfg, store, &mut cleanup).await;
    for d in cleanup.alpn {
        store.challenges.write().unwrap().remove(&d);
    }
    for t in cleanup.tokens {
        store.http_tokens.write().unwrap().remove(&t);
    }
    if cleanup.duckdns
        && let Method::DuckDns { token } = &cfg.method
        && let Err(e) = duckdns_txt(token, &cfg.domains[0], None).await
    {
        warn!("acme: clearing the DuckDNS TXT record: {e:#}");
    }
    r
}

async fn issue_inner(cfg: &Config, store: &CertStore, cleanup: &mut Cleanup) -> Result<()> {
    let acct = account(cfg).await?;
    let ids: Vec<Identifier> = cfg.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = acct
        .new_order(&NewOrder::new(&ids))
        .await
        .context("creating the order")?;
    let ty = match cfg.method {
        Method::TlsAlpn => ChallengeType::TlsAlpn01,
        Method::Http(_) => ChallengeType::Http01,
        Method::DuckDns { .. } => ChallengeType::Dns01,
    };
    let mut authzs = order.authorizations();
    while let Some(a) = authzs.next().await {
        let mut authz = a?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            s => bail!("authorization is {s:?}"),
        }
        let mut ch = authz
            .challenge(ty.clone())
            .ok_or_else(|| anyhow!("the CA doesn't offer the {ty:?} check"))?;
        let domain = match ch.identifier().identifier {
            Identifier::Dns(d) => d.to_ascii_lowercase(),
            other => bail!("unexpected identifier {other:?}"),
        };
        let ka = ch.key_authorization();
        match &cfg.method {
            Method::TlsAlpn => {
                let c = challenge_cert(&domain, ka.digest().as_ref())?;
                store.challenges.write().unwrap().insert(domain.clone(), c);
                cleanup.alpn.push(domain.clone());
            }
            Method::Http(_) => {
                store
                    .http_tokens
                    .write()
                    .unwrap()
                    .insert(ch.token.clone(), ka.as_str().to_string());
                cleanup.tokens.push(ch.token.clone());
            }
            Method::DuckDns { token } => {
                let value = ka.dns_value();
                cleanup.duckdns = true;
                duckdns_txt(token, &domain, Some(&value)).await?;
                wait_for_txt(&domain, &value).await;
            }
        }
        ch.set_ready().await.context("telling the CA to check")?;
    }
    let status = order
        .poll_ready(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(1))
                .timeout(Duration::from_secs(180)),
        )
        .await
        .context("waiting for the CA's check")?;
    if status != OrderStatus::Ready {
        let detail = order
            .state()
            .error
            .as_ref()
            .map(|e| format!(": {e}"))
            .unwrap_or_default();
        bail!("the CA's check failed (order {status:?}){detail}");
    }
    let key_pem = order.finalize().await.context("finalizing the order")?;
    let chain_pem = order
        .poll_certificate(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(1))
                .timeout(Duration::from_secs(180)),
        )
        .await
        .context("downloading the certificate")?;
    let ck = certified_key(chain_pem.as_bytes(), key_pem.as_bytes())?;
    let dir = cfg.cert_dir();
    std::fs::create_dir_all(&dir)?;
    write_private(&dir.join("key.pem"), key_pem.as_bytes())?;
    write_private(&dir.join("cert.pem"), chain_pem.as_bytes())?;
    store.set(ck);
    Ok(())
}

// ---- HTTP-01 ----

/// Answer HTTP-01 checks on `addr`, and redirect everything else to HTTPS.
pub async fn serve_http01(addr: SocketAddr, store: Arc<CertStore>) -> Result<()> {
    use axum::extract::{Path as UrlPath, State};
    use axum::http::{HeaderMap, StatusCode, Uri, header};
    use axum::response::{IntoResponse, Response};

    async fn token(State(s): State<Arc<CertStore>>, UrlPath(t): UrlPath<String>) -> Response {
        match s.http_token(&t) {
            Some(ka) => ([(header::CONTENT_TYPE, "text/plain")], ka).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
    async fn redirect(headers: HeaderMap, uri: Uri) -> Response {
        let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
        let host = host
            .rsplit_once(':')
            .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
            .map_or(host, |(h, _)| h);
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, format!("https://{host}{path}"))],
        )
            .into_response()
    }
    let app = axum::Router::new()
        .route("/.well-known/acme-challenge/{token}", axum::routing::get(token))
        .fallback(redirect)
        .with_state(store);
    let l = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("acme: listening on {addr}"))?;
    info!("acme: answering HTTP-01 checks on {addr}");
    axum::serve(l, app).await?;
    Ok(())
}

// ---- DNS-01 through DuckDNS ----

fn duckdns_name(domain: &str) -> Result<&str> {
    let sub = domain
        .strip_suffix(".duckdns.org")
        .context("--acme-dns duckdns needs a NAME.duckdns.org domain")?;
    Ok(sub.rsplit('.').next().unwrap_or(sub))
}

/// Set (or with `None`, clear) the TXT record of a DuckDNS name.
async fn duckdns_txt(token: &str, domain: &str, value: Option<&str>) -> Result<()> {
    let base = std::env::var("TC_DUCKDNS_URL").unwrap_or_else(|_| "https://www.duckdns.org/update".into());
    let name = duckdns_name(domain)?;
    let q = match value {
        Some(v) => format!("domains={name}&token={token}&txt={v}&verbose=true"),
        None => format!("domains={name}&token={token}&txt=removed&clear=true&verbose=true"),
    };
    let (status, body) = http_get(&format!("{base}?{q}")).await.context("calling DuckDNS")?;
    if status != 200 || !body.trim_start().starts_with("OK") {
        bail!(
            "DuckDNS refused the TXT update (HTTP {status}: {}); check TC_DUCKDNS_TOKEN",
            body.trim()
        );
    }
    Ok(())
}

/// Wait until DuckDNS's name servers serve the TXT record, so Let's Encrypt
/// sees it when it looks. Gives up (and lets the CA try anyway) after 3 minutes.
async fn wait_for_txt(domain: &str, value: &str) {
    let name = format!("_acme-challenge.{domain}");
    let servers: Vec<SocketAddr> = match std::env::var("TC_DUCKDNS_NS") {
        Ok(s) => s.split(',').filter_map(|a| a.trim().parse().ok()).collect(),
        Err(_) => {
            let mut v = Vec::new();
            for ns in ["ns1.duckdns.org", "ns2.duckdns.org", "ns3.duckdns.org"] {
                if let Ok(mut a) = tokio::net::lookup_host((ns, 53)).await
                    && let Some(a) = a.find(|a| a.is_ipv4())
                {
                    v.push(a);
                }
            }
            v
        }
    };
    if servers.is_empty() {
        warn!("acme: can't reach DuckDNS's name servers to check the record; waiting a minute instead");
        tokio::time::sleep(Duration::from_secs(60)).await;
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let mut all = true;
        for s in &servers {
            if !txt_query(*s, &name).await.is_ok_and(|v| v.iter().any(|t| t == value)) {
                all = false;
            }
        }
        if all {
            info!("acme: DuckDNS serves the TXT record");
            return;
        }
        if tokio::time::Instant::now() > deadline {
            warn!("acme: DuckDNS doesn't serve the TXT record yet; asking the CA to check anyway");
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// The TXT strings of `name`, asked of one name server over UDP.
async fn txt_query(server: SocketAddr, name: &str) -> Result<Vec<String>> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.trim_end_matches('.').split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 16, 0, 1]);
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&q, server).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await??;
    parse_txt_response(&buf[..n], id)
}

fn skip_name(m: &[u8], mut p: usize) -> Result<usize> {
    loop {
        let l = *m.get(p).context("truncated")? as usize;
        if l == 0 {
            return Ok(p + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Ok(p + 2);
        }
        p += 1 + l;
    }
}

fn parse_txt_response(m: &[u8], id: u16) -> Result<Vec<String>> {
    if m.len() < 12 || u16::from_be_bytes([m[0], m[1]]) != id {
        bail!("bad DNS response");
    }
    let qd = u16::from_be_bytes([m[4], m[5]]) as usize;
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(m, p)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        p = skip_name(m, p)?;
        let h = m.get(p..p + 10).context("truncated")?;
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let len = u16::from_be_bytes([h[8], h[9]]) as usize;
        p += 10;
        let rdata = m.get(p..p + len).context("truncated")?;
        p += len;
        if ty == 16 {
            let mut i = 0;
            let mut s = Vec::new();
            while i < rdata.len() {
                let l = rdata[i] as usize;
                s.extend_from_slice(rdata.get(i + 1..i + 1 + l).context("truncated")?);
                i += 1 + l;
            }
            out.push(String::from_utf8_lossy(&s).into_owned());
        }
    }
    Ok(out)
}

/// A minimal HTTP(S) GET, for DuckDNS's API: (status, body).
async fn http_get(url: &str) -> Result<(u16, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("unsupported URL {url}");
    };
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p.parse()?),
        _ => (hostport, if tls { 443 } else { 80 }),
    };
    // The DuckDNS token is in the URL: plain HTTP only to this machine
    // (the tests' fake DuckDNS), never across a network.
    if !tls && !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        bail!("refusing to send the request unencrypted to {host}: use https://");
    }
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailconnect-ssh\r\nConnection: close\r\n\r\n");
    let tcp = tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect((host, port))).await??;
    let mut raw = Vec::new();
    let io = async {
        if tls {
            let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(name, tcp)
                .await?;
            s.write_all(req.as_bytes()).await?;
            // Some servers close without TLS close_notify; take what arrived.
            let _ = s.read_to_end(&mut raw).await;
        } else {
            let mut s = tcp;
            s.write_all(req.as_bytes()).await?;
            s.read_to_end(&mut raw).await?;
        }
        anyhow::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(30), io).await??;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").context("bad HTTP response")?;
    let status: u16 = head.split_whitespace().nth(1).context("bad HTTP status")?.parse()?;
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = if chunked { dechunk(body) } else { body.to_string() };
    Ok((status, body))
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = s.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(size.trim().split(';').next().unwrap_or(""), 16) else {
            break;
        };
        if n == 0 || rest.len() < n {
            break;
        }
        out.push_str(&rest[..n]);
        s = rest[n..].strip_prefix("\r\n").unwrap_or(&rest[n..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(names: &[&str]) -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    #[test]
    fn domains_are_checked() {
        assert_eq!(
            parse_domains("Hub.Example.com, hub.example.com,b.example.org.").unwrap(),
            vec!["hub.example.com", "b.example.org"]
        );
        for bad in ["", "localhost", "10.0.0.1", "a..b", "-a.b", "a_b.example.com"] {
            assert!(parse_domains(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn labels_keep_staging_and_production_apart() {
        let mut c = Config {
            domains: vec!["hub.example.com".into()],
            email: None,
            directory: LETS_ENCRYPT.into(),
            ca_root: None,
            method: Method::TlsAlpn,
            dir: "/x/acme".into(),
        };
        assert_eq!(c.cert_dir(), PathBuf::from("/x/acme/letsencrypt-hub.example.com"));
        c.directory = LETS_ENCRYPT_STAGING.into();
        assert_eq!(c.account_file(), PathBuf::from("/x/acme/account-staging.json"));
        c.directory = "https://127.0.0.1:14000/dir".into();
        assert!(c.label().starts_with("acme-"));
    }

    #[test]
    fn renewal_after_two_thirds() {
        let day = 86400;
        assert_eq!(renew_at(0, 90 * day), 60 * day);
    }

    #[test]
    fn cert_info_and_saved_certificate() {
        let (cert, key) = self_signed(&["hub.example.com", "alt.example.com"]);
        let (nb, na, names) = cert_info(cert.as_bytes()).unwrap();
        assert!(na > nb);
        assert_eq!(names, vec!["hub.example.com", "alt.example.com"]);
        let dir = std::env::temp_dir().join(format!("tc-acme-{}", std::process::id()));
        let cfg = Config {
            domains: vec!["hub.example.com".into()],
            email: None,
            directory: LETS_ENCRYPT.into(),
            ca_root: None,
            method: Method::TlsAlpn,
            dir: dir.clone(),
        };
        assert!(load_saved(&cfg).is_none());
        std::fs::create_dir_all(cfg.cert_dir()).unwrap();
        std::fs::write(cfg.cert_dir().join("cert.pem"), &cert).unwrap();
        std::fs::write(cfg.cert_dir().join("key.pem"), &key).unwrap();
        assert!(load_saved(&cfg).is_some());
        // A different name means a new certificate.
        let other = Config {
            domains: vec!["hub.example.com".into(), "new.example.com".into()],
            ..cfg.clone()
        };
        assert!(load_saved(&other).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn challenge_certificate_has_the_acme_extension() {
        let digest = Sha256::digest(b"token.thumbprint");
        let ck = challenge_cert("hub.example.com", &digest).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&ck.cert[0]).unwrap();
        // id-pe-acmeIdentifier 1.3.6.1.5.5.7.1.31, critical, OCTET STRING of the digest.
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        assert!(ext.critical);
        assert_eq!(&ext.value[2..], digest.as_slice());
    }

    #[derive(Debug)]
    struct AcceptAll;

    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// The TLS listener serves challenge certificates only to `acme-tls/1`
    /// connections for names being validated, and the current one otherwise.
    #[tokio::test]
    async fn resolver_answers_tls_alpn_checks() {
        let (cert, key) = self_signed(&["hub.example.com"]);
        let store = CertStore::new(certified_key(cert.as_bytes(), key.as_bytes()).unwrap());
        let digest = Sha256::digest(b"ka");
        store.challenges.write().unwrap().insert(
            "hub.example.com".into(),
            challenge_cert("hub.example.com", &digest).unwrap(),
        );
        let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(store.clone());
        sc.alpn_protocols = vec![crate::ALPN.to_vec(), ALPN_ACME.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));

        async fn handshake(acceptor: tokio_rustls::TlsAcceptor, sni: &str, alpn: &[u8]) -> Option<Vec<u8>> {
            let (a, b) = tokio::io::duplex(1 << 16);
            let server = tokio::spawn(async move { acceptor.accept(a).await.is_ok() });
            // Like an ACME validator, accept the challenge certificate's
            // critical acmeIdentifier extension, which webpki would refuse.
            let mut cc =
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAll))
                    .with_no_client_auth();
            cc.alpn_protocols = vec![alpn.to_vec()];
            let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
            let r = tokio_rustls::TlsConnector::from(Arc::new(cc)).connect(name, b).await;
            let _ = server.await;
            r.ok()
                .and_then(|s| s.get_ref().1.peer_certificates().map(|c| c[0].to_vec()))
        }

        let leaf = handshake(acceptor.clone(), "hub.example.com", ALPN_ACME)
            .await
            .expect("challenge handshake");
        let (_, c) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        assert!(
            c.extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        );
        let leaf = handshake(acceptor.clone(), "hub.example.com", crate::ALPN)
            .await
            .expect("normal handshake");
        let (_, c) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        assert!(
            !c.extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        );
        assert!(
            handshake(acceptor, "other.example.com", ALPN_ACME).await.is_none(),
            "no challenge for other names"
        );
    }

    #[tokio::test]
    async fn http01_answers_tokens_and_redirects() {
        let (cert, key) = self_signed(&["hub.example.com"]);
        let store = CertStore::new(certified_key(cert.as_bytes(), key.as_bytes()).unwrap());
        store
            .http_tokens
            .write()
            .unwrap()
            .insert("tok".into(), "tok.thumb".into());
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        tokio::spawn(serve_http01(addr, store));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (s, body) = http_get(&format!("http://{addr}/.well-known/acme-challenge/tok"))
            .await
            .unwrap();
        assert_eq!((s, body.as_str()), (200, "tok.thumb"));
        let (s, _) = http_get(&format!("http://{addr}/.well-known/acme-challenge/nope"))
            .await
            .unwrap();
        assert_eq!(s, 404);
        let (s, _) = http_get(&format!("http://{addr}/portal")).await.unwrap();
        assert_eq!(s, 301);
    }

    #[tokio::test]
    async fn duckdns_api_calls() {
        // A fake DuckDNS that records requests.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let ok = line.contains("token=good");
                seen2.lock().unwrap().push(line);
                let body = if ok { "OK\n1.2.3.4\n\nUPDATED" } else { "KO" };
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        // SAFETY: tests in this module that read TC_DUCKDNS_URL run only here.
        unsafe { std::env::set_var("TC_DUCKDNS_URL", format!("http://{addr}/update")) };
        duckdns_txt("good", "myhub.duckdns.org", Some("abc")).await.unwrap();
        duckdns_txt("good", "myhub.duckdns.org", None).await.unwrap();
        assert!(duckdns_txt("bad", "myhub.duckdns.org", Some("abc")).await.is_err());
        let seen = seen.lock().unwrap();
        assert!(seen[0].contains("domains=myhub&token=good&txt=abc"));
        assert!(seen[1].contains("clear=true"));
        assert!(duckdns_name("example.com").is_err());
        assert_eq!(duckdns_name("a.myhub.duckdns.org").unwrap(), "myhub");
    }

    #[test]
    fn txt_response_parsing() {
        // Response for _acme-challenge.x.duckdns.org TXT "hello" "world".
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for l in ["_acme-challenge", "x", "duckdns", "org"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 16, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 12]);
        m.extend_from_slice(b"\x05hello\x05world");
        assert_eq!(parse_txt_response(&m, 0x1234).unwrap(), vec!["helloworld"]);
        assert!(parse_txt_response(&m, 0x9999).is_err());
    }

    #[test]
    fn chunked_bodies() {
        assert_eq!(dechunk("2\r\nOK\r\n3\r\n\nhi\r\n0\r\n\r\n"), "OK\nhi");
    }
}
