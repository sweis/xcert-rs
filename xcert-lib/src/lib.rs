//! xcert-lib: Library for parsing and inspecting X.509 certificates.
//!
//! Provides a high-level API for extracting information from X.509 certificates
//! in PEM or DER format, computing fingerprints, checking validity, and
//! converting between formats.
//!
//! # Quick start
//!
//! ```
//! use xcert_lib::{parse_cert, check_host, check_expiry, DigestAlgorithm};
//!
//! let pem = b"-----BEGIN CERTIFICATE-----
//! MIIBiTCCAS+gAwIBAgIUInw7Y00tAIhFdBFi5M1og2/KIxUwCgYIKoZIzj0EAwIw
//! GjEYMBYGA1UEAwwPZG9jLmV4YW1wbGUuY29tMB4XDTI2MDIyNDIyNTEwNFoXDTM2
//! MDIyMjIyNTEwNFowGjEYMBYGA1UEAwwPZG9jLmV4YW1wbGUuY29tMFkwEwYHKoZI
//! zj0CAQYIKoZIzj0DAQcDQgAEnbgGc2we2bznirfCnCL0jLWhp5CGeHCCLNHy4Ov8
//! wSTejbLzOMnMuZepxDfbe/hPws0c6ogJ/NWRicjUJadGoaNTMFEwHQYDVR0OBBYE
//! FLNAZyPx2/js7qydbcgQFkFGlK0DMB8GA1UdIwQYMBaAFLNAZyPx2/js7qydbcgQ
//! FkFGlK0DMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOoF0Ud/
//! 6i9fvri/Adh9jLQuVWYzoGpfYilbhnlwXGu5AiBfstNy020jTiex8ctuh+VHGJ58
//! tf6RlyGcTwetIa12sw==
//! -----END CERTIFICATE-----";
//!
//! // Parse a certificate (auto-detects PEM vs DER)
//! let cert = parse_cert(pem).unwrap();
//! assert_eq!(cert.version, 3);
//! assert!(cert.subject_string().contains("doc.example.com"));
//!
//! // Extract fields
//! assert_eq!(cert.public_key.algorithm, "EC");
//!
//! // Compute fingerprint
//! let fp = cert.fingerprint(DigestAlgorithm::Sha256);
//! assert!(fp.contains(':')); // colon-separated hex
//!
//! // Check hostname (matches CN since no SAN DNS entries)
//! assert!(check_host(&cert, "doc.example.com"));
//! assert!(!check_host(&cert, "other.example.com"));
//!
//! // Check expiry (cert is valid for 10 years)
//! assert!(check_expiry(&cert, 86400)); // valid for at least 1 day
//! ```

mod check;
mod convert;
mod display;
mod fields;
mod fingerprint;
pub mod oid;
mod parser;
mod util;
pub mod verify;

pub use check::{check_email, check_expiry, check_host, check_ip};
pub use convert::{der_to_pem, pem_to_der};
pub use display::{display_text, to_json};
pub use fields::{
    AiaEntry, CertificateInfo, DateTime, DigestAlgorithm, DistinguishedName, Extension,
    ExtensionValue, PublicKeyInfo, SanEntry,
};
pub use fingerprint::compute_fingerprint;
pub use parser::{parse_cert, parse_der, parse_pem};
pub use util::is_pem;
pub use verify::{
    check_crl_revocation, find_system_ca_bundle, is_certificate_chain, parse_pem_chain,
    parse_pem_crl, resolve_purpose, verify_chain, verify_chain_with_options, verify_pem_chain,
    verify_pem_chain_with_options, verify_with_untrusted, ChainCertInfo, TrustStore,
    VerificationResult, VerifyOptions, VerifyPolicy,
};

/// Errors returned by xcert-lib.
#[derive(Debug, thiserror::Error)]
pub enum XcertError {
    #[error("Failed to parse certificate: {0}")]
    ParseError(String),

    #[error("Invalid PEM format: {0}")]
    PemError(String),

    #[error("Invalid DER format: {0}")]
    DerError(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Verification error: {0}")]
    VerifyError(String),
}
