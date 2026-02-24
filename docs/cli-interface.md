# CLI Interface: `xcert`

A simplified, intuitive command-line tool for inspecting X.509 certificates.

## Design Principles

1. **Subcommand-based** -- uses `xcert <command>` instead of a flat list of flags.
   This is more discoverable and consistent with modern CLI conventions.
2. **Sensible defaults** -- `xcert show cert.pem` does the right thing without flags.
3. **Input auto-detection** -- PEM vs DER is detected automatically from content;
   no `-inform` flag needed. Reads from stdin if no file is given.
4. **Consistent output** -- human-readable by default, with `--json` for machine
   consumption. No separate flags to control dozens of output formatting sub-options.
5. **No signing** -- this tool is read-only. Certificate creation and signing are
   separate concerns handled by other tools.
6. **Batch mode** -- all commands accept a directory as input to process multiple
   certificate files in parallel.

## Commands

### `xcert show` -- Display certificate information

The primary command. Displays a human-readable summary of the certificate.

```
xcert show [OPTIONS] [FILE]

Arguments:
  [FILE]  Certificate file (PEM or DER), or directory. Reads from stdin if omitted.

Options:
  --der          Force DER input parsing (default: auto-detect)
  --pem          Force PEM input parsing (default: auto-detect)
  --json         Output in JSON format
  --all          Show all fields including signature bytes
  --recurse      Recurse into subdirectories (directory mode)
```

Examples:
```bash
xcert show cert.pem
xcert show --json cert.pem
xcert show --all cert.pem
xcert show /etc/ssl/certs/               # batch mode
xcert show /etc/ssl/certs/ --recurse     # recursive
```

### `xcert field` -- Extract a single field

Print one specific field from the certificate. Useful for scripting.

```
xcert field <FIELD> [OPTIONS] [FILE]

Fields:
  subject        Subject distinguished name
  issuer         Issuer distinguished name
  serial         Serial number (colon-separated hex)
  not-before     Validity start date
  not-after      Validity end date
  fingerprint    Certificate fingerprint (default: SHA-256)
  public-key     Public key in PEM format
  modulus        RSA public key modulus (hex)
  exponent       RSA public exponent
  curve          EC named curve (e.g. P-256, P-384, P-521)
  emails         Email addresses from subject and SAN
  dns-names      DNS names from SAN extension
  ip-addrs       IP addresses from SAN extension
  san            All Subject Alternative Name entries
  ocsp-url       OCSP responder URL(s) from AIA
  key-usage      Key Usage extension value
  ext-key-usage  Extended Key Usage extension value
  extensions     All extensions (names and values)

Options:
  [FILE]         Certificate file or directory. Reads from stdin if omitted.
  --der          Force DER input parsing
  --pem          Force PEM input parsing
  --digest <ALG> Hash algorithm for fingerprint (sha256, sha384, sha512, sha1).
                 Default: sha256.
  --ext <NAME>   Filter extensions by name or OID
  --json         Output in JSON format
  --recurse      Recurse into subdirectories (directory mode)
```

Examples:
```bash
xcert field fingerprint cert.pem
xcert field serial cert.pem
xcert field san --json cert.pem
xcert field fingerprint --digest sha384 cert.pem
xcert field dns-names cert.pem
xcert field curve ec-cert.pem
xcert field extensions --ext "Basic Constraints" cert.pem
xcert field serial /etc/ssl/certs/ --json   # batch
```

### `xcert check` -- Validate certificate properties

Check whether the certificate satisfies certain conditions. Returns exit code 0
for pass, 1 for fail. Designed for use in scripts and CI pipelines.

```
xcert check <CHECK> <VALUE> [OPTIONS] [FILE]

Checks:
  expiry <DURATION>  Check if cert expires within the given duration
  host <HOSTNAME>    Check if cert matches hostname
  email <EMAIL>      Check if cert matches email address
  ip <ADDRESS>       Check if cert matches IP address (v4 or v6)

Duration formats:
  30d, 1w, 2h30m, 1w3d, 90s, 5min, or plain seconds (e.g., 2592000)
  Units: s, m/min, h/hr, d/day, w/week, month, y/year

Options:
  [FILE]              Certificate file or directory. Reads from stdin if omitted.
  --der               Force DER input parsing
  --pem               Force PEM input parsing
  --json              Output in JSON format
  --failures-only     Only show failures (batch mode)
  --recurse           Recurse into subdirectories (directory mode)
```

Examples:
```bash
xcert check expiry 30d cert.pem
xcert check expiry 1w cert.pem
xcert check host www.example.com cert.pem
xcert check ip 93.184.216.34 cert.pem
xcert check email user@example.com cert.pem

# Batch mode
xcert check expiry 30d /etc/ssl/certs/
xcert check expiry 7d --failures-only /etc/ssl/certs/

# Scripting
if xcert check expiry 7d cert.pem; then
  echo "Certificate is valid for at least 7 more days"
fi
```

### `xcert convert` -- Convert between formats

Convert certificates between PEM and DER encodings.

```
xcert convert [OPTIONS] [FILE] [OUTPUT]

Arguments:
  [FILE]         Input certificate file. Reads from stdin if omitted.
  [OUTPUT]       Output file. Writes to stdout if omitted.

Options:
  --to <FORMAT>  Output format: pem, der. Inferred from output file extension
                 if not specified.
  --der          Force DER input parsing
  --pem          Force PEM input parsing
```

Examples:
```bash
xcert convert cert.pem cert.der          # PEM to DER (format inferred)
xcert convert cert.der cert.pem          # DER to PEM (format inferred)
xcert convert cert.pem --to der          # Explicit format, stdout
cat cert.pem | xcert convert --to der > cert.der
```

### `xcert verify` -- Verify a certificate chain

Verify a certificate chain against a trust store. Returns exit code 0 for
success, 2 for verification failure.

```
xcert verify [OPTIONS] [FILE]

Arguments:
  [FILE]  PEM file containing the certificate chain (leaf first, then
          intermediates), or a directory of certificate files.
          Reads from stdin if omitted.

Options:
  --hostname <HOST>     Hostname to verify against the leaf certificate's SAN/CN
  --CAfile <FILE>       PEM file containing trusted CA certificates
                        (default: system trust store)
  --CApath <DIR>        Directory of trusted CA certificates in PEM format
  --untrusted <FILE>    PEM file with untrusted intermediate certificates
  --purpose <PURPOSE>   Required EKU: sslserver, sslclient, smimesign,
                        codesign, any, or a custom OID
  --partial-chain       Accept any chain cert as a trust anchor
  --no-check-time       Skip validity date checks
  --attime <EPOCH>      Verify at a specific Unix timestamp
  --verify-depth <N>    Maximum chain depth (default: 32)
  --verify-email <EMAIL> Verify email against the leaf certificate
  --verify-ip <IP>      Verify IP against the leaf certificate
  --show-chain          Show subject/issuer for each cert in the chain
  --CRLfile <FILE>      PEM file containing CRL(s) for revocation checking
  --crl-check           Check CRL revocation for the leaf certificate
  --crl-check-all       Check CRL revocation for all certs in the chain
  --json                Output in JSON format
  --failures-only       Only show failures (batch mode)
  --recurse             Recurse into subdirectories (directory mode)
```

Examples:
```bash
xcert verify chain.pem
xcert verify --hostname www.example.com chain.pem
xcert verify --CAfile my-ca.pem chain.pem
xcert verify --untrusted intermediates.pem leaf.pem
xcert verify --partial-chain --CAfile trusted.pem leaf.pem
xcert verify --no-check-time chain.pem
xcert verify --purpose sslserver chain.pem
xcert verify --CRLfile revoked.crl.pem --crl-check chain.pem
xcert verify --json chain.pem
xcert verify --failures-only /etc/ssl/certs/  # batch
```

## Comparison with `openssl`

| openssl | xcert | Notes |
|---|---|---|
| `openssl x509 -text -noout -in cert.pem` | `xcert show cert.pem` | |
| `openssl x509 -subject -noout -in cert.pem` | `xcert field subject cert.pem` | |
| `openssl x509 -issuer -noout -in cert.pem` | `xcert field issuer cert.pem` | |
| `openssl x509 -serial -noout -in cert.pem` | `xcert field serial cert.pem` | |
| `openssl x509 -dates -noout -in cert.pem` | `xcert field not-before` / `not-after` | Separate fields |
| `openssl x509 -fingerprint -sha256 -noout` | `xcert field fingerprint cert.pem` | SHA-256 default |
| `openssl x509 -pubkey -noout -in cert.pem` | `xcert field public-key cert.pem` | |
| `openssl x509 -modulus -noout -in cert.pem` | `xcert field modulus cert.pem` | |
| `openssl x509 -email -noout -in cert.pem` | `xcert field emails cert.pem` | |
| `openssl x509 -ext subjectAltName` | `xcert field san cert.pem` | |
| `openssl x509 -ocsp_uri -noout` | `xcert field ocsp-url cert.pem` | |
| `openssl x509 -checkend 3600` | `xcert check expiry 1h cert.pem` | Duration support |
| `openssl x509 -checkhost foo.com` | `xcert check host foo.com cert.pem` | |
| `openssl x509 -checkip 1.2.3.4` | `xcert check ip 1.2.3.4 cert.pem` | |
| `openssl x509 -checkemail a@b.com` | `xcert check email a@b.com cert.pem` | |
| `openssl x509 -outform DER -in x -out y` | `xcert convert x y` | Auto-detect |
| `openssl verify chain.pem` | `xcert verify chain.pem` | |
| `openssl verify -CAfile ca.pem cert.pem` | `xcert verify --CAfile ca.pem cert.pem` | |
| `openssl verify -untrusted int.pem leaf.pem` | `xcert verify --untrusted int.pem leaf.pem` | |
| `openssl verify -partial_chain cert.pem` | `xcert verify --partial-chain cert.pem` | |
| `openssl verify -crl_check -CRLfile x` | `xcert verify --crl-check --CRLfile x` | |

## What is NOT included (by design)

The following `openssl x509` features are intentionally excluded:

- **Signing** (`-key`, `-CA`, `-signkey`, `-req`, `-new`, `-x509toreq`) -- use a
  dedicated signing tool
- **Trust settings** (`-trustout`, `-addtrust`, `-addreject`, `-setalias`) -- an
  OpenSSL-specific concept
- **Name formatting options** (`-nameopt`) -- the tool uses a single consistent
  format. Use `--json` for machine parsing.
- **Subject/issuer hashes** (`-subject_hash`, `-issuer_hash`) -- OpenSSL-specific
  directory indexing
- **Extension injection** (`-extfile`, `-extensions`) -- part of signing
- **C source output** (`-C`) -- removed even from OpenSSL 3.0
