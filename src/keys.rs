//! SSH key handling. Every machine (and the hub) has one Ed25519 key, stored
//! in OpenSSH format. Its public half, in `ssh-ed25519 AAAA...` form, is the
//! machine's identity.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, PublicKey};

/// Load the key at `path`, or create one there (mode 0600) if missing.
pub fn load_or_create(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return PrivateKey::from_openssh(&text).with_context(|| format!("parsing {}", path.display()));
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).context("generating key")?;
    let text = key.to_openssh(LineEnding::LF).context("encoding key")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = crate::private_file(fs::OpenOptions::new().write(true).create_new(true))
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(key)
}

/// Identity string for a public key: `<algorithm> <base64>`, without comment.
pub fn key_id(key: &PublicKey) -> String {
    let s = key.to_openssh().unwrap_or_default();
    s.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// Parse an identity string back to a public key.
pub fn parse_key_id(s: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(s.trim()).context("parsing public key")
}

/// SHA-256 fingerprint in OpenSSH style (`SHA256:...`).
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

/// The X25519 private key matching an Ed25519 machine key (the same
/// conversion as libsodium's `crypto_sign_ed25519_sk_to_curve25519`). Used
/// for end-to-end encryption of relayed traffic, so peers need no second key.
pub fn x25519_private(key: &PrivateKey) -> Result<[u8; 32]> {
    use sha2::Digest;
    let kp = key.key_data().ed25519().context("machine key is not Ed25519")?;
    let h = sha2::Sha512::digest(kp.private.to_bytes());
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    Ok(s)
}

/// The X25519 public key matching an Ed25519 public key.
pub fn x25519_public(key: &PublicKey) -> Result<[u8; 32]> {
    let ed = key.key_data().ed25519().context("key is not Ed25519")?;
    let point = curve25519_dalek::edwards::CompressedEdwardsY(ed.0)
        .decompress()
        .context("invalid Ed25519 public key")?;
    Ok(point.to_montgomery().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_conversion_matches() {
        let k = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let sk = x25519_private(&k).unwrap();
        let pk = x25519_public(k.public_key()).unwrap();
        assert_eq!(curve25519_dalek::MontgomeryPoint::mul_base_clamped(sk).to_bytes(), pk);
    }

    #[test]
    fn create_then_load_same_key() {
        let dir = std::env::temp_dir().join(format!("tc-keytest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let p = dir.join("k");
        let a = load_or_create(&p).unwrap();
        let b = load_or_create(&p).unwrap();
        assert_eq!(key_id(a.public_key()), key_id(b.public_key()));
        let id = key_id(a.public_key());
        assert!(id.starts_with("ssh-ed25519 "));
        assert_eq!(key_id(&parse_key_id(&id).unwrap()), id);
        fs::remove_dir_all(&dir).unwrap();
    }
}
