//! The TLS layer that wraps SSH on port 443.
//!
//! TLS here is camouflage and an extra authentication layer: the SSH session
//! inside it is what authenticates machines and the hub. Clients reach the
//! hub with either a publicly trusted certificate (for example Let's Encrypt)
//! or a self-signed one whose SHA-256 fingerprint they pin.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Lower-case hex SHA-256 of a DER certificate.
pub fn cert_fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Normalise a user-supplied fingerprint: strip `sha256:` and colons, lower-case.
pub fn normalise_fingerprint(s: &str) -> Result<String> {
    let s = s.trim();
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("SHA256:"))
        .unwrap_or(s);
    let s: String = s.chars().filter(|c| *c != ':').collect::<String>().to_lowercase();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("TLS fingerprint must be 64 hex digits (SHA-256 of the certificate)");
    }
    Ok(s)
}

pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    /// Fingerprint of the leaf certificate, for clients that pin it.
    pub fingerprint: String,
    /// DNS names in the leaf certificate.
    pub names: Vec<String>,
    /// Whether the certificate was generated here (clients must pin it).
    pub self_signed: bool,
}

/// ALPN protocol id for browsers: the web portal shares port 443 with SSH.
pub const ALPN_HTTP: &[u8] = b"http/1.1";

impl ServerTls {
    /// The same certificate, also offering HTTP/1.1 for the web portal. SSH
    /// clients ask for `tc-ssh/1` and still get it; browsers don't offer it.
    pub fn with_http(&self) -> Arc<ServerConfig> {
        let mut c = (*self.config).clone();
        c.alpn_protocols = vec![crate::ALPN.to_vec(), ALPN_HTTP.to_vec()];
        Arc::new(c)
    }
}

fn build_server(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<ServerTls> {
    let leaf = certs.first().ok_or_else(|| anyhow!("no certificate"))?;
    let fingerprint = cert_fingerprint(leaf);
    let names = webpki::EndEntityCert::try_from(leaf)
        .map(|c| c.valid_dns_names().map(|n| n.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;
    config.alpn_protocols = vec![crate::ALPN.to_vec()];
    Ok(ServerTls {
        config: Arc::new(config),
        fingerprint,
        names,
        self_signed: false,
    })
}

/// Load a PEM certificate chain and key.
pub fn server_from_pem(cert: &Path, key: &Path) -> Result<ServerTls> {
    let certs = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading {}", key.display()))?;
    build_server(certs, key)
}

/// Load the self-signed certificate in `dir`, creating it for `names` if missing.
pub fn server_self_signed(dir: &Path, names: Vec<String>) -> Result<ServerTls> {
    let cert_path = dir.join("tls-cert.pem");
    let key_path = dir.join("tls-key.pem");
    if !cert_path.exists() || !key_path.exists() {
        let ck = rcgen::generate_simple_self_signed(names).context("generating certificate")?;
        fs::create_dir_all(dir)?;
        write_private(&key_path, ck.signing_key.serialize_pem().as_bytes())?;
        fs::write(&cert_path, ck.cert.pem())?;
    }
    let mut t = server_from_pem(&cert_path, &key_path)?;
    t.self_signed = true;
    Ok(t)
}

/// An ephemeral self-signed certificate, for direct peer listeners where TLS
/// is only camouflage (SSH host keys authenticate the peer).
pub fn server_ephemeral() -> Result<ServerTls> {
    let ck = rcgen::generate_simple_self_signed(vec!["tailconnect.invalid".to_string()])?;
    let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der()).map_err(|e| anyhow!(e))?;
    build_server(vec![ck.cert.der().clone()], key)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// How a client checks the server's certificate.
#[derive(Debug, Clone)]
pub enum Verify {
    /// Publicly trusted CA (Mozilla root store).
    WebPki,
    /// Only this exact certificate (SHA-256 hex of its DER).
    Pinned(String),
    /// Anything. Used only for direct peer sessions, which authenticate the
    /// peer by its SSH host key.
    Any,
}

pub fn client_config(verify: Verify) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let mut config = match verify {
        Verify::WebPki => {
            let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Verify::Pinned(fp) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier::new(Some(fp))))
            .with_no_client_auth(),
        Verify::Any => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier::new(None)))
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![crate::ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Accepts the certificate whose fingerprint matches (or any, if `None`),
/// while still checking that the server holds the certificate's key.
#[derive(Debug)]
struct PinVerifier {
    fingerprint: Option<String>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn new(fingerprint: Option<String>) -> Self {
        PinVerifier {
            fingerprint,
            algs: provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.fingerprint {
            None => Ok(ServerCertVerified::assertion()),
            Some(want) if *want == cert_fingerprint(end_entity) => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "server certificate does not match the pinned fingerprint".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_normalisation() {
        let fp = "AB:".repeat(31) + "AB";
        assert_eq!(normalise_fingerprint(&fp).unwrap(), "ab".repeat(32));
        assert_eq!(
            normalise_fingerprint(&format!("sha256:{}", "0".repeat(64))).unwrap(),
            "0".repeat(64)
        );
        assert!(normalise_fingerprint("abc").is_err());
    }
}
