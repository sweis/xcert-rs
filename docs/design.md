# Design Document: xcert

## 1. Overview

`xcert` is a Rust command-line tool and library for parsing, displaying, and
verifying X.509 certificates. It is a read-only replacement for the inspection
and verification features of `openssl x509` and `openssl verify`, with a
simplified, modern CLI interface.

### Goals
- Parse X.509 certificates from PEM and DER formats
- Display certificate information in human-readable and JSON formats
- Extract individual fields for scripting
- Check certificate validity (expiry, hostname, email, IP)
- Verify certificate chains against system or custom trust stores
- CRL revocation checking
- Convert between PEM and DER encodings
- Provide a library interface (`xcert-lib`) usable programmatically

### Non-Goals
- Certificate creation, signing, or modification
- Trust store management (creation or modification)
- Private key handling

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       xcert (CLI binary)                     │
│  ┌──────────┐ ┌───────┐ ┌───────┐ ┌─────────┐ ┌─────────┐  │
│  │ show cmd │ │field  │ │check  │ │convert  │ │ verify  │  │
│  │          │ │cmd    │ │cmd    │ │cmd      │ │ cmd     │  │
│  └────┬─────┘ └──┬────┘ └──┬────┘ └────┬────┘ └────┬────┘  │
│       └──────────┴─────────┴────────────┴───────────┘       │
│                             │                                │
│                    ┌────────┴─────────┐                      │
│                    │    xcert-lib     │                      │
│                    │    (library)     │                      │
│                    └────────┬─────────┘                      │
│                             │                                │
│       ┌─────────────┬───────┼───────┬──────────────┐        │
│       │             │       │       │              │        │
│  ┌────┴─────┐ ┌─────┴────┐ │ ┌─────┴────┐  ┌──────┴─────┐  │
│  │ Parser   │ │ Display  │ │ │ Check    │  │  Verify    │  │
│  │ module   │ │ module   │ │ │ module   │  │  module    │  │
│  └────┬─────┘ └──────────┘ │ └──────────┘  └──────┬─────┘  │
│       │                    │                       │        │
│       │              ┌─────┴──────┐    ┌───────────┤        │
│       │              │ Fingerprint│    │ TrustStore│        │
│       │              │ module     │    │ WebPKI    │        │
│       │              └────────────┘    │ CRL       │        │
│       │                                └───────────┘        │
└───────┼─────────────────────────────────────────────────────┘
        │
   ┌────┴───────────────┐
   │  x509-parser crate │  (external dependency)
   └────────────────────┘
```

### Crate Structure

The project is organized as a Cargo workspace with two crates:

```
xcert-rs/
├── Cargo.toml              # Workspace root
├── xcert/                   # CLI binary crate
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── xcert-lib/               # Library crate
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs           # Public API and re-exports
│   │   ├── parser.rs        # PEM/DER parsing, format detection
│   │   ├── display.rs       # Human-readable formatting
│   │   ├── fields.rs        # CertificateInfo, Extension types, field extraction
│   │   ├── check.rs         # Validity checks (expiry, hostname, IP, email)
│   │   ├── convert.rs       # PEM <-> DER conversion
│   │   ├── fingerprint.rs   # Digest computation (SHA-256/384/512/SHA-1)
│   │   ├── oid.rs           # Centralized OID string constants
│   │   ├── util.rs          # Shared utilities (hex, base64, PEM detection)
│   │   └── verify/          # Certificate chain verification
│   │       ├── mod.rs        # Public verify API
│   │       ├── chain.rs      # Chain building and verification orchestration
│   │       ├── checks.rs     # Individual check functions (time, constraints, etc.)
│   │       ├── constraints.rs # Name Constraints validation
│   │       ├── crl.rs        # CRL revocation checking
│   │       ├── helpers.rs    # Verification helper functions
│   │       ├── trust_store.rs # TrustStore: system and custom CA management
│   │       └── webpki.rs     # WebPKI/CABF Baseline Requirements policy checks
│   └── tests/
│       ├── integration.rs    # Integration tests using generated test certs
│       ├── pyca_cryptography.rs  # Tests against pyca/cryptography vectors
│       └── zlint.rs          # Tests against zlint certificate corpus
├── testdata/                # Test certificates and external vectors
│   ├── certs/               # Generated test certs (via generate.sh)
│   ├── zlint/               # Git submodule: zmap/zlint
│   ├── x509-limbo/          # Git submodule: C2SP/x509-limbo
│   └── pyca-cryptography/   # Git submodule: pyca/cryptography
├── fuzz/                    # Fuzzing targets (cargo-fuzz)
└── docs/                    # Documentation
```

## 3. Dependencies

### xcert-lib

| Crate | Version | Purpose |
|-------|---------|---------|
| `x509-parser` | 0.18 | Core X.509 DER/PEM parsing (with `verify` feature) |
| `sha2` | 0.10 | SHA-256/384/512 fingerprints |
| `sha1` | 0.10 | SHA-1 fingerprints (legacy compat) |
| `serde` | 1 | Serialization (with `derive` feature) |
| `serde_json` | 1 | JSON output |
| `thiserror` | 2 | Error types |
| `hex` | 0.4 | Hex encoding for fingerprints/serial |
| `base64` | 0.22 | Base64 encoding for PEM conversion |
| `openssl-probe` | 0.2 | System trust store path detection |
| `time` | 0.3 | Date/time formatting |
| `colored` | 2 | Colored terminal output in display module |

### xcert (CLI)

| Crate | Version | Purpose |
|-------|---------|---------|
| `xcert-lib` | path | The library |
| `clap` | 4 | CLI argument parsing (with `derive` feature) |
| `anyhow` | 1 | Error handling in binary |
| `humantime` | 2 | Human-readable duration parsing (30d, 1w, etc.) |
| `rayon` | 1 | Parallel directory processing |
| `walkdir` | 2 | Recursive directory traversal |
| `colored` | 2 | Colored terminal output |
| `serde` | 1 | JSON batch output serialization |
| `serde_json` | 1 | JSON output |

## 4. Library API Design

### Core Types

```rust
/// A parsed X.509 certificate with extracted fields.
pub struct CertificateInfo {
    pub version: u32,
    pub serial: String,                  // Hex string (colon-separated)
    pub signature_algorithm: String,
    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub not_before: DateTime,
    pub not_after: DateTime,
    pub public_key: PublicKeyInfo,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
    raw_der: Vec<u8>,                    // Raw DER for fingerprints
}

/// Distinguished name with ordered components.
pub struct DistinguishedName {
    pub components: Vec<(String, String)>,  // e.g., [("CN", "example.com"), ("O", "Org")]
}

/// Public key summary.
pub struct PublicKeyInfo {
    pub algorithm: String,       // "RSA", "EC", "Ed25519", "Ed448", etc.
    pub key_size: Option<u32>,   // Bit size (e.g., 2048 for RSA)
    pub curve: Option<String>,   // e.g., "P-256" for EC keys
    pub modulus: Option<String>, // Hex string for RSA
    pub exponent: Option<u64>,   // Public exponent for RSA (e.g., 65537)
    pub pem: String,             // PEM-encoded SubjectPublicKeyInfo
}

/// Strongly-typed extension values.
pub enum ExtensionValue {
    BasicConstraints { ca: bool, path_len: Option<u32> },
    KeyUsage(Vec<String>),
    ExtendedKeyUsage(Vec<String>),
    SubjectAltName(Vec<SanEntry>),
    SubjectKeyIdentifier(String),
    AuthorityKeyIdentifier { key_id: Option<String>, issuer: Option<String> },
    AuthorityInfoAccess(Vec<AiaEntry>),
    CrlDistributionPoints(Vec<String>),
    CertificatePolicies(Vec<String>),
    NsComment(String),
    Raw(String),  // Hex dump for unknown extensions
}

pub enum SanEntry {
    Dns(String),
    Email(String),
    Ip(String),
    Uri(String),
    DirName(String),
    Other(String),
}
```

### Public API Functions

```rust
// --- Parsing ---
pub fn parse_cert(input: &[u8]) -> Result<CertificateInfo, XcertError>;
pub fn parse_pem(input: &[u8]) -> Result<CertificateInfo, XcertError>;
pub fn parse_der(input: &[u8]) -> Result<CertificateInfo, XcertError>;

// --- Checks ---
pub fn check_expiry(cert: &CertificateInfo, seconds: u64) -> bool;
pub fn check_host(cert: &CertificateInfo, hostname: &str) -> bool;
pub fn check_email(cert: &CertificateInfo, email: &str) -> bool;
pub fn check_ip(cert: &CertificateInfo, ip: &str) -> bool;

// --- Conversion ---
pub fn der_to_pem(der: &[u8]) -> String;
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError>;

// --- Display ---
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String;
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError>;

// --- Verification ---
pub fn verify_chain(chain_der: &[Vec<u8>], store: &TrustStore,
                    hostname: Option<&str>) -> Result<VerificationResult, XcertError>;
pub fn verify_chain_with_options(chain_der: &[Vec<u8>], store: &TrustStore,
                                 hostname: Option<&str>, opts: &VerifyOptions)
    -> Result<VerificationResult, XcertError>;
pub fn verify_with_untrusted(leaf_der: &[u8], untrusted_pem: &[u8],
                              store: &TrustStore, hostname: Option<&str>,
                              opts: &VerifyOptions)
    -> Result<VerificationResult, XcertError>;

// --- Trust Store ---
pub struct TrustStore { /* ... */ }
impl TrustStore {
    pub fn system() -> Result<Self, XcertError>;
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, XcertError>;
    pub fn from_pem_file(path: &Path) -> Result<Self, XcertError>;
    pub fn add_pem_bundle(&mut self, pem_data: &[u8]) -> Result<usize, XcertError>;
    pub fn add_pem_directory(&mut self, dir: &Path) -> Result<usize, XcertError>;
}

pub struct VerifyOptions {
    pub check_time: bool,
    pub partial_chain: bool,
    pub purpose: Option<String>,
    pub at_time: Option<i64>,
    pub verify_depth: Option<usize>,
    pub verify_email: Option<String>,
    pub verify_ip: Option<String>,
    pub crl_ders: Vec<Vec<u8>>,
    pub crl_check_leaf: bool,
    pub crl_check_all: bool,
    pub policy: VerifyPolicy,
}

pub enum VerifyPolicy { Default, WebPki }
```

## 5. CLI Design

See [cli-interface.md](cli-interface.md) for the full CLI specification.

The CLI binary is a thin layer over the library. Each subcommand maps directly
to library functions:

| Subcommand | Library functions used |
|---|---|
| `xcert show` | `parse_cert()` + `display_text()` or `to_json()` |
| `xcert field <F>` | `parse_cert()` + corresponding `CertificateInfo` method |
| `xcert check <C>` | `parse_cert()` + `check_*()` |
| `xcert convert` | `pem_to_der()` or `der_to_pem()` |
| `xcert verify` | `verify_chain_with_options()` + `TrustStore` |

All commands support directory mode (batch processing) with `--json` and
`--failures-only` options, plus `--recurse` for recursive directory traversal.

## 6. Input Format Detection

Auto-detection algorithm:

1. If `--pem` or `--der` is specified, use that format.
2. If the input starts with `-----BEGIN` (after stripping leading whitespace),
   treat as PEM.
3. Otherwise, treat as DER.

## 7. Output Formatting

### Human-readable (default)

The `show` command produces output structured similarly to `openssl x509 -text`
but with cleaner formatting and colored output in terminals.

### JSON

The `--json` flag produces structured JSON output. All fields are present, with
extensions as typed objects. Bulk operations return a `results` array with a
`summary` object.

## 8. Hostname Matching

The `check host` command implements RFC 6125 hostname matching:

1. Check SAN DNS entries first (if SAN extension exists).
2. Wildcard matching: `*.example.com` matches `foo.example.com` but not
   `foo.bar.example.com` or `example.com`.
3. Only fall back to CN matching if no SAN DNS entries exist.
4. Case-insensitive comparison.

## 9. Test Strategy

279 tests organized across the library:

- **Unit tests** in each module for internal logic
- **Integration tests** in `xcert-lib/tests/` using test vectors in
  `testdata/certs/` and comparing against reference outputs
- **External test vectors** from three git submodules: zlint, x509-limbo,
  pyca/cryptography
- **Fuzz targets** for parsing robustness

Test categories:
1. Parsing tests -- PEM, DER, auto-detect, invalid input, chain bundles
2. Field extraction tests -- each field against reference output
3. Fingerprint tests -- SHA-256, SHA-1 against reference
4. Display tests -- full text output structure
5. Check tests -- expiry, hostname, email, IP (positive and negative)
6. Conversion tests -- PEM->DER->PEM roundtrip
7. Key algorithm tests -- RSA, ECDSA P-256, ECDSA P-384, Ed25519
8. Verification tests -- chain validation, trust anchoring, CRL, WebPKI
9. Edge cases -- minimal certs, UTF-8 subjects, many extensions, expired certs
