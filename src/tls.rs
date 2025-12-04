use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

#[derive(Debug)]
pub struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub(crate) fn load_chia_certs()
-> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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

pub fn load_cert_key(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load cert chain
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    // Load pkcs8 private key
    let mut key_reader = BufReader::new(File::open(key_path)?);
    let keys: Vec<_> = pkcs8_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        anyhow::bail!("No private key found");
    }

    Ok((cert_chain, PrivateKeyDer::Pkcs8(keys[0].clone_key())))
}

pub fn make_client_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<ClientConfig> {
    let root = RootCertStore::empty();

    let mut cfg = ClientConfig::builder()
        .with_root_certificates(root)
        .with_client_auth_cert(cert_chain, key)?;

    // InsecureSkipVerify equivalent
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoCertVerifier));

    Ok(cfg)
}
