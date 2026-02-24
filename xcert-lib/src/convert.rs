//! PEM <-> DER format conversion.

use crate::util;
use crate::XcertError;

/// Convert DER-encoded certificate bytes to a PEM string.
///
/// # Examples
///
/// ```
/// let pem = xcert_lib::der_to_pem(&[0x30, 0x82, 0x01, 0x00]);
/// assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
/// assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
/// ```
pub fn der_to_pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        util::base64_wrap(der)
    )
}

/// Convert a PEM-encoded certificate to DER bytes.
///
/// # Examples
///
/// ```
/// let pem = b"-----BEGIN CERTIFICATE-----
/// MIIBiTCCAS+gAwIBAgIUInw7Y00tAIhFdBFi5M1og2/KIxUwCgYIKoZIzj0EAwIw
/// GjEYMBYGA1UEAwwPZG9jLmV4YW1wbGUuY29tMB4XDTI2MDIyNDIyNTEwNFoXDTM2
/// MDIyMjIyNTEwNFowGjEYMBYGA1UEAwwPZG9jLmV4YW1wbGUuY29tMFkwEwYHKoZI
/// zj0CAQYIKoZIzj0DAQcDQgAEnbgGc2we2bznirfCnCL0jLWhp5CGeHCCLNHy4Ov8
/// wSTejbLzOMnMuZepxDfbe/hPws0c6ogJ/NWRicjUJadGoaNTMFEwHQYDVR0OBBYE
/// FLNAZyPx2/js7qydbcgQFkFGlK0DMB8GA1UdIwQYMBaAFLNAZyPx2/js7qydbcgQ
/// FkFGlK0DMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOoF0Ud/
/// 6i9fvri/Adh9jLQuVWYzoGpfYilbhnlwXGu5AiBfstNy020jTiex8ctuh+VHGJ58
/// tf6RlyGcTwetIa12sw==
/// -----END CERTIFICATE-----";
///
/// let der = xcert_lib::pem_to_der(pem).unwrap();
/// assert_eq!(der[0], 0x30); // DER SEQUENCE tag
/// ```
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError> {
    // Skip any leading comments or metadata before the PEM block.
    let pem_input = match util::find_pem_start(pem) {
        Some(offset) => pem.get(offset..).unwrap_or(pem),
        None => pem,
    };

    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem_input)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;
    Ok(parsed.contents)
}
