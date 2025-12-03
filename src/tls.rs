use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, PrivateKey, ServerName};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::SystemTime;

struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Equivalent to InsecureSkipVerify
        // Don't verify anything and just return ok
        Ok(ServerCertVerified::assertion())
    }
}

pub(crate) fn load_chia_certs() -> anyhow::Result<(Vec<Certificate>, PrivateKey)> {
    // TODO: Load certificate paths from environment
    let cert_path = std::env::var("CHIA_CERT_PATH")
        .unwrap_or_else(|_| "~/.chia/config/ssl/full_node/private_full_node.crt".to_string());
    let key_path = std::env::var("CHIA_KEY_PATH")
        .unwrap_or_else(|_| "~/.chia/config/ssl/full_node/private_full_node.key".to_string());

    // Expand ~ to home directory
    let cert_path = cert_path.replace(
        '~',
        &std::env::var("HOME").unwrap_or_else(|_| ".".to_string()),
    );
    let key_path = key_path.replace(
        '~',
        &std::env::var("HOME").unwrap_or_else(|_| ".".to_string()),
    );

    load_cert_key(&cert_path, &key_path)
}

fn load_cert_key(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Vec<Certificate>, PrivateKey)> {
    // Load cert chain
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let keys = pkcs8_private_keys(&mut key_reader)?;
    if keys.is_empty() {
        anyhow::bail!("No private key found");
    }

    let key = PrivateKey(keys[0].clone());

    Ok((cert_chain, key))
}

pub(crate) fn make_client_config(
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
) -> anyhow::Result<Arc<ClientConfig>> {
    let mut cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_client_auth_cert(cert_chain, key)?;

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoCertVerifier));

    Ok(Arc::new(cfg))
}
