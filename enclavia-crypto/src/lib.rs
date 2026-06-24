//! Library face of `enclavia-crypto`, exposing the pieces of the in-enclave
//! KMS client that are worth reusing and testing outside the binary:
//! the hand-rolled SigV4 signer and the shared TLS client configuration.
//!
//! The `enclavia-crypto` binary uses these directly; the real-AWS smoke
//! example (`examples/kms_real_smoke.rs`) uses them to exercise the exact
//! signer + TLS settings against real KMS over a TCP connection (the
//! in-enclave path is identical except the socket is a vsock relay).

use std::sync::Arc;

pub mod sigv4;

/// The rustls client configuration used for every TLS connection to AWS
/// KMS: validate the server certificate against the Amazon (Mozilla
/// `webpki-roots`) trust anchors compiled into this binary (hence
/// PCR-measured, so the host cannot swap roots), pinned to the `ring`
/// crypto provider so the musl EIF builds without a C toolchain.
pub fn kms_tls_config() -> tokio_rustls::rustls::ClientConfig {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth()
}
