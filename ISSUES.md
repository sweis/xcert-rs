# Known Issues

Issues identified during code review. Ordered roughly by severity.

## Security / Correctness

### 1. CRL validity dates are not checked

`check_crl_revocation()` in `verify.rs:1280-1319` parses each CRL and checks
serial numbers, but never validates the CRL's `thisUpdate` / `nextUpdate`
fields. An expired CRL (one whose `nextUpdate` is in the past) is silently
accepted, which means revocation data may be stale. RFC 5280 Section 6.3.3
requires that the current time falls within the CRL validity period.

---

### 2. CRL signature is not verified for root certificates

In `verify.rs:745-748`, the issuer for CRL signature verification is looked up
as `parsed[i + 1]`. For the last certificate in the chain (the root), there is
no `i + 1`, so `issuer` is `None`. In `check_crl_revocation()` at line 1300,
when `issuer_cert` is `None`, the CRL signature verification is skipped
entirely. This means a CRL could be forged for the root CA without detection.

---

### 3. `--crl-check` without `--CRLfile` silently does nothing

In `main.rs:546-552`, if no `--CRLfile` is provided, `crl_ders` is set to an
empty `Vec`. The `crl_check_leaf` / `crl_check_all` flags are still set
(`main.rs:570-571`), but the empty CRL list means no revocation checking
actually occurs. The user is not warned that their `--crl-check` flag had no
effect. Should either require `--CRLfile` when `--crl-check` is used, or at
minimum print a warning.

---

### 4. `der_wrap()` panics on untrusted input

`parser.rs:273-276` uses `assert!()` to enforce a 16 MiB size limit:

```rust
assert!(
    len <= 0xFF_FFFF,
    "DER content length {len} exceeds maximum supported (16 MiB)"
);
```

This is called during SPKI PEM construction from parsed certificate data. While
the comment claims this "cannot occur for certificate SPKI data," a malformed
certificate could trigger this and crash the process. Should return
`Result<Vec<u8>, XcertError>` instead of panicking.

---

### 5. RSA parameter extraction silently returns incorrect values on failure

`parser.rs:193-214`: When `extract_rsa_params()` fails to parse the DER
structure, it falls back to `(hex::encode_upper(data), data.len() * 8, 65537)`
without any indication of failure. The fallback key size includes DER encoding
overhead, so a 2048-bit key may be reported as ~2160 bits. Callers have no way
to distinguish valid results from the incorrect fallback.

---

## Code Quality

### 6. O(n^2) email deduplication in `CertificateInfo::emails()`

`fields.rs:267` uses `Vec::contains()` for deduplication, which is O(n) per
call inside a loop over SAN entries. For certificates with many SAN email
entries, this results in O(n^2) behavior. Should use a `HashSet` or collect
first and deduplicate after.

---

### 7. Duplicate GeneralName formatting logic

`parser.rs:485-504` has two nearly identical functions:
- `general_name_to_san_entry()` converts `GeneralName` to `SanEntry`
- `format_general_name()` converts `GeneralName` to `String`

Both have the same match arms for DNS, Email, IP, and URI. The only difference
is the return type. One could call the other, or a shared helper could extract
the common logic.

---

### 8. Unnecessary Vec allocation for PEM detection

`parser.rs:20-25` collects into a `Vec<u8>` just to call `starts_with()`:

```rust
let trimmed = input.iter()
    .skip_while(|b| b.is_ascii_whitespace())
    .take(11).copied().collect::<Vec<_>>();
trimmed.starts_with(b"-----BEGIN")
```

The same check in `main.rs:479-486` has the same pattern. Could use iterator
comparison directly without any heap allocation.

---

### 9. `base64_wrap()` uses unnecessary intermediate allocations

`util.rs:22-30` converts a base64 String to bytes, chunks it, converts each
chunk back to `&str` via `from_utf8`, collects into a `Vec<&str>`, then joins.
Since base64 output is always valid UTF-8 ASCII, the `from_utf8` check is
redundant, and the intermediate Vec can be avoided by writing chunks directly
to a pre-allocated String.

---

### 10. Duplicate extension search methods in `fields.rs`

`fields.rs:278-319`: The methods `san_entries()`, `ocsp_urls()`,
`key_usage()`, and `ext_key_usage()` each iterate `self.extensions` with an
identical `for/if let` pattern, differing only in which `ExtensionValue`
variant they match. Could be consolidated with a generic helper.

---

## Minor

### 11. CRL reason code uses Debug formatting

`verify.rs:1311` formats the CRL reason code with `format!("{:?}", rc.1)`,
which produces Rust debug output like `KeyCompromise` instead of a
human-readable form like `keyCompromise` or the OpenSSL-style
`Key Compromise`. Should map reason codes to standard display strings.

---

### 12. No X.509 version validation

`parser.rs:68` computes `let version = tbs.version.0 + 1` without checking
that the value is in the valid range (0, 1, or 2 for v1, v2, v3). A
certificate with version 255 would display "Version: 256" without any warning.
