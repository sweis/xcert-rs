# xcert-rs: Rust x509 Certificate Inspection Utility

[![CI](https://github.com/sweis/xcert-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/sweis/xcert-rs/actions/workflows/ci.yml)

A fast, memory-safe command-line tool for inspecting X.509 certificates. Read-only alternative to `openssl x509` with JSON output and colored terminal display.

## Installation

```bash
cargo install --path xcert
```

Or build from source:

```bash
cargo build --release
# Binary at target/release/xcert
```

## Usage

### Show certificate details

```bash
xcert show cert.pem
xcert show --json cert.pem          # JSON output
xcert show --all cert.pem           # Include signature bytes

# Bulk: show all certs in a directory
xcert show /etc/ssl/certs/ --json
xcert show /etc/ssl/certs/ --recurse
```

### Extract a single field

```bash
xcert field subject cert.pem
xcert field serial cert.pem
xcert field not-after cert.pem
xcert field fingerprint cert.pem
xcert field fingerprint --digest sha384 cert.pem
xcert field curve cert.pem            # EC curve name (e.g. P-256)
xcert field dns-names cert.pem        # DNS names from SAN
xcert field ip-addrs cert.pem         # IP addresses from SAN
xcert field san --json cert.pem
xcert field public-key cert.pem

# Bulk: extract field from all certs in a directory
xcert field serial /etc/ssl/certs/ --json
xcert field not-after /etc/ssl/certs/ --recurse
```

Available fields:

| Field | Description |
|---|---|
| `subject` | Subject distinguished name |
| `issuer` | Issuer distinguished name |
| `serial` | Serial number (colon-separated hex) |
| `not-before` | Not Before date (ISO 8601) |
| `not-after` | Not After date (ISO 8601) |
| `fingerprint` | Certificate fingerprint (default: SHA-256; use `--digest` for sha384/sha512/sha1) |
| `public-key` | Subject public key in PEM format |
| `modulus` | RSA modulus in hex (RSA certificates only) |
| `exponent` | RSA public exponent (RSA certificates only) |
| `curve` | EC named curve, e.g. P-256, P-384, P-521 (EC certificates only) |
| `emails` | Email addresses from subject DN `emailAddress` attribute and SAN `rfc822Name` entries |
| `dns-names` | DNS names from the SAN extension |
| `ip-addrs` | IP addresses from the SAN extension (IPv4 and IPv6) |
| `san` | All Subject Alternative Name entries (DNS, Email, IP, URI, DirName) |
| `ocsp-url` | OCSP responder URL(s) from AIA extension |
| `key-usage` | Key Usage extension values |
| `ext-key-usage` | Extended Key Usage extension values |
| `extensions` | All extensions (use `--ext` to filter by name or OID) |

### Check certificate properties

Returns exit code 0 for pass, 1 for fail.

```bash
xcert check expiry 30d cert.pem     # Valid for 30+ days?
xcert check expiry 1w cert.pem      # Valid for 1+ week?
xcert check host example.com cert.pem
xcert check email user@example.com cert.pem
xcert check ip 93.184.216.34 cert.pem

# Bulk: check all certs in a directory
xcert check expiry 30d /etc/ssl/certs/
xcert check expiry 30d /etc/ssl/certs/ --json
xcert check expiry 7d --failures-only /etc/ssl/certs/
```

Check types:

| Check | Value | Description |
|---|---|---|
| `expiry` | Duration | Pass if cert is valid for at least this much longer |
| `host` | Hostname | Pass if hostname matches SAN DNS entries or subject CN (RFC 6125 wildcards supported) |
| `email` | Email address | Pass if email matches SAN `rfc822Name` entries or subject `emailAddress` attribute (case-insensitive) |
| `ip` | IP address | Pass if IP matches SAN IP entries (IPv4 or IPv6, normalized for comparison) |

Duration formats: `30d`, `1w`, `2h30m`, `1w3d`, or plain seconds (e.g., `2592000`).
Units: `s`, `m`/`min`, `h`/`hr`, `d`/`day`, `w`/`week`, `month`, `y`/`year`.

### Verify certificate chains

```bash
xcert verify chain.pem
xcert verify --hostname example.com chain.pem
xcert verify --CAfile ca.pem chain.pem
xcert verify --untrusted intermediates.pem leaf.pem
xcert verify --json chain.pem

# Bulk: verify all certs in a directory
xcert verify --CAfile ca.pem /etc/ssl/certs/ --json
xcert verify --failures-only /etc/ssl/certs/
```

Exit code 0 = valid, 2 = invalid.

Options:

| Option | Description |
|---|---|
| `--hostname <NAME>` | Verify hostname against the leaf certificate's SAN/CN |
| `--CAfile <FILE>` | PEM file containing trusted CA certificates (default: system trust store) |
| `--CApath <DIR>` | Directory of trusted CA certificates in PEM format |
| `--untrusted <FILE>` | PEM file with untrusted intermediate certificates for chain building |
| `--purpose <PURPOSE>` | Required Extended Key Usage: `sslserver`, `sslclient`, `smimesign`, `codesign`, `any`, or a custom OID |
| `--partial-chain` | Accept any certificate in the chain as a trust anchor |
| `--no-check-time` | Skip validity date checks |
| `--attime <EPOCH>` | Verify at a specific Unix timestamp instead of current time |
| `--verify-depth <N>` | Maximum chain depth (default: 32) |
| `--verify-email <EMAIL>` | Verify email address against the leaf certificate's SAN/subject |
| `--verify-ip <IP>` | Verify IP address against the leaf certificate's SAN |
| `--show-chain` | Display subject and issuer for each certificate in the verified chain |
| `--CRLfile <FILE>` | PEM file containing CRL(s) for revocation checking |
| `--crl-check` | Check CRL revocation for the leaf certificate (requires `--CRLfile`) |
| `--crl-check-all` | Check CRL revocation for all certificates in the chain (requires `--CRLfile`) |

### Convert between formats

```bash
xcert convert cert.pem cert.der     # PEM to DER
xcert convert cert.der cert.pem     # DER to PEM
xcert convert cert.pem --to der     # Explicit format (stdout)
```

## JSON Output

All commands support `--json` for machine-readable output. Bulk operations return:

```json
{
  "results": [
    {"file": "path/to/cert.pem", "success": true, "data": {...}},
    {"file": "path/to/bad.pem", "success": false, "error": "..."}
  ],
  "summary": {"total": 10, "succeeded": 8, "failed": 2}
}
```

Each result has `success: true` with a `data` field, or `success: false` with an `error` field.
The `data` field contains command-specific output (e.g., full certificate info for `show`, the extracted value for `field`, a `{"check", "value", "passed"}` object for `check`, or a `{"valid", "errors"}` object for `verify`).

The `summary` counts processing outcomes: `succeeded` is the number of files processed without errors, and `failed` is the number of files that could not be read or parsed. For `check` and `verify`, the pass/fail status of each individual check is in the per-result `data`, not in the summary.

## Features

- Auto-detection of PEM vs DER format
- Colored terminal output (dates, hex values, URLs, strings)
- Parallel directory processing via rayon
- Certificate chain verification against system or custom trust store
- CRL revocation checking (`--CRLfile`, `--crl-check`, `--crl-check-all`)
- RSA, ECDSA (P-256/P-384/P-521), Ed25519, Ed448 key types
- SHA-256/384/512/SHA-1 fingerprints
- Memory-safe Rust with `unsafe` forbidden

## Testing

```bash
cargo test
```

276 tests covering parsing, verification, checks, conversions, and compatibility with external test vectors.

### External test vector suites

Three git submodules provide additional test vectors from external projects. Tests skip gracefully when submodules are not initialized.

```bash
# Initialize all submodules
git submodule update --init

# Run tests (submodule tests now included)
cargo test
```

| Submodule | Source | What it tests |
|---|---|---|
| `testdata/zlint` | [zmap/zlint](https://github.com/zmap/zlint) | 2000+ real-world and edge-case certificates |
| `testdata/x509-limbo` | [C2SP/x509-limbo](https://github.com/C2SP/x509-limbo) | RFC 5280, WebPKI, and path-building verification vectors |
| `testdata/pyca-cryptography` | [pyca/cryptography](https://github.com/pyca/cryptography) | Algorithm diversity (Ed25519, Ed448, RSA-PSS, DSA) and NIST PKITS suite |

## Fuzzing

```bash
cargo +nightly fuzz run parse_cert -- -max_total_time=60
```

Four fuzz targets: `parse_cert`, `parse_der`, `parse_pem`, `roundtrip`.

## Security

- `unsafe` code denied at workspace level
- Clippy warns on `unwrap()`, `expect()`, `panic!()`
- `cargo audit` for dependency scanning

## Performance

See [PERF.md](PERF.md) for benchmarks. xcert is 3.7x-4.5x faster than OpenSSL for common operations.

## License

[MIT License](LICENSE)
