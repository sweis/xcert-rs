# Known Issues

Issues identified during code review. Issues 1–25 have been fixed.
Issues 26–35 were identified in the Round 3 post-merge review.

## Security / Correctness

### ~~1. CRL validity dates are not checked~~ FIXED

**Fix:** `check_crl_revocation()` now takes a `now_ts` parameter and validates
the CRL's `thisUpdate` / `nextUpdate` fields per RFC 5280 Section 6.3.3.
CRLs that are not yet valid or have expired are skipped.

---

### ~~2. CRL signature is not verified for root certificates~~ FIXED

**Fix:** The CRL check loop now pre-parses the trusted root certificate when
available and uses it (or the cert itself for self-signed roots) as the issuer
for CRL signature verification. The issuer is never `None` for CRL checks.

---

### ~~3. `--crl-check` without `--CRLfile` silently does nothing~~ FIXED

**Fix:** `xcert verify` now validates that `--CRLfile` is provided when
`--crl-check` or `--crl-check-all` is used, and exits with an error if not.

---

### ~~4. `der_wrap()` panics on untrusted input~~ FIXED

**Fix:** `der_wrap()` now returns `Result<Vec<u8>, XcertError>` instead of
using `assert!()`. Errors are propagated through `build_spki_pem()` which
also returns `Result`. No more panics on malformed input.

---

### ~~5. RSA parameter extraction silently returns incorrect values on failure~~ FIXED

**Fix:** `extract_rsa_params()` now returns `Option<(String, u32, u64)>`.
On parse failure, the caller sets modulus, key_size, and exponent to `None`
rather than reporting incorrect fallback values.

---

## Code Quality

### ~~6. O(n^2) email deduplication in `CertificateInfo::emails()`~~ FIXED

**Fix:** Replaced `Vec::contains()` deduplication with a `HashSet` for O(1)
lookup per insertion.

---

### ~~7. Duplicate GeneralName formatting logic~~ FIXED

**Fix:** `format_general_name()` now calls `general_name_to_san_entry()` and
extracts the inner string, eliminating the duplicate match arms.

---

### ~~8. Unnecessary Vec allocation for PEM detection~~ FIXED

**Fix:** Both `parse_cert()` in `parser.rs` and the convert command in
`main.rs` now use iterator-based comparison (`iter().take(10).eq(...)`)
instead of collecting into a `Vec<u8>`.

---

### ~~9. `base64_wrap()` uses unnecessary intermediate allocations~~ FIXED

**Fix:** Replaced byte-chunking with `from_utf8` and `Vec<&str>::join()` with
direct string slicing into a pre-allocated `String`. No intermediate Vec or
UTF-8 validation needed since base64 is ASCII.

---

### ~~10. Duplicate extension search methods in `fields.rs`~~ FIXED

**Fix:** Replaced manual `for/if let/return` loops in `san_entries()`,
`ocsp_urls()`, `key_usage()`, and `ext_key_usage()` with idiomatic
`find_map()` calls.

---

### ~~11. `dns_name_matches_constraint` allocates on every call~~ FIXED

**Fix:** Replaced `name.ends_with(&format!(".{}", constraint))` with a
non-allocating length + suffix + byte check.

---

### ~~12. `ip_matches_constraint` has duplicate IPv4/IPv6 masking loops~~ FIXED

**Fix:** Consolidated into a single generic implementation using
`split_at(addr_len)` and `Iterator::zip().all()`.

---

### ~~13. `check_host` collects SAN DNS entries into unnecessary Vec~~ FIXED

**Fix:** Replaced `Vec<&str>` collect + `is_empty()` check + iterate with a
single-pass loop that tracks `has_san_dns` and matches in one iteration.

---

### ~~14. `to_oneline` uses intermediate Vec and `replace()` chain~~ FIXED

**Fix:** Replaced `collect::<Vec<_>>().join(", ")` with direct `String`
building, and replaced the three `.replace()` calls with a single char-by-char
escape loop.

---

## Minor

### ~~15. CRL reason code uses Debug formatting~~ FIXED

**Fix:** Added `format_crl_reason()` function that maps `ReasonCode` debug
representations to RFC 5280-style camelCase strings (e.g., `keyCompromise`,
`cACompromise`, `cessationOfOperation`).

---

### ~~16. No X.509 version validation~~ FIXED

**Fix:** `build_certificate_info()` now validates that the X.509 version
field is 0, 1, or 2 (v1, v2, v3) and returns `XcertError::ParseError` for
unsupported version values.

---

### ~~17. `check_email` and `check_ip` use verbose loops~~ FIXED

**Fix:** Simplified both functions to use iterator `.any()` and `matches!()`
instead of explicit `for` loops with early return.

---

### ~~18. RSA exponent silently defaults to 65537 on parse failure~~ FIXED

**Fix:** `extract_rsa_params()` now returns `None` (via `?`) when the exponent
cannot be parsed from the DER sequence, instead of silently substituting 65537.

---

### ~~19. DER encoding errors silently swallowed in SPKI PEM generation~~ FIXED

**Fix:** `build_spki_pem()` now propagates DER encoding errors from
`to_der_vec()` via `map_err` + `?` instead of using `unwrap_or_default()`
and NULL-byte fallbacks.

---

### ~~20. `check_expiry` skips notBefore validation for non-positive timestamps~~ FIXED

**Fix:** Replaced mixed signed/unsigned comparison with consistent signed
arithmetic (`not_before > (now as i64)`), correctly handling pre-epoch
timestamps without skipping validation.

---

### ~~21. Hardcoded DER length limit magic number~~ FIXED

**Fix:** Extracted `MAX_DER_CONTENT_LEN` named constant (0xFF_FFFF / 16 MiB)
with documentation explaining the 3-byte DER length field limit.

---

### ~~22. Inconsistent IPv6 hex formatting between parser and check modules~~ FIXED

**Fix:** `normalize_ip()` in `check.rs` now uses uppercase hex (`{:X}`)
matching `format_ip_bytes()` in `parser.rs` for consistent OpenSSL-compatible
IPv6 formatting.

---

### ~~23. Duplicate PEM detection logic in parser.rs and main.rs~~ FIXED

**Fix:** Extracted `util::is_pem()` shared utility function, exposed as
`xcert_lib::is_pem()`. Both `parse_cert()` and the CLI convert command
now call the shared function.

---

### ~~24. OID comparisons use `format!()` instead of `to_id_string()`~~ FIXED

**Fix:** Replaced `format!("{}", oid)` and `format!("{}", attr.attr_type())`
with `oid.to_id_string()` / `attr.attr_type().to_id_string()` in `verify.rs`
(EKU check, extract_cn, verify_email, check_name_constraints) and `parser.rs`
(build_dn). More idiomatic and avoids format machinery overhead.

---

### ~~25. Redundant bounds checks on `used` vector in `verify_with_untrusted`~~ FIXED

**Fix:** Replaced `used.get(idx).copied().unwrap_or(true)` and
`used.get_mut(idx)` with direct indexing (`used[idx]`), since the vector
is guaranteed to have the same length as the `intermediates` iterator.

---

## Round 3: Post-merge comprehensive review

Issues identified after merging significant new features (directory/batch mode,
chain detection, Name Constraints, keyCertSign, trusted root validation,
`find_system_ca_bundle()`).

### 26. Duplicate hostname/email/IP matching logic in `check.rs` and `verify.rs`

**Severity:** Medium (maintenance risk)

`check.rs` and `verify.rs` both implement the same matching logic for hostnames,
emails, and IP addresses:

- `check_host()` (check.rs:41) vs `verify_hostname()` (verify.rs:1012)
- `check_email()` (check.rs:73) vs `verify_email()` (verify.rs:1058)
- `check_ip()` (check.rs:83) vs `verify_ip()` (verify.rs:1088)

The `check.rs` versions operate on `CertificateInfo` (parsed high-level type),
while `verify.rs` versions operate on `X509Certificate` (raw x509-parser type).
Both use the same `util::hostname_matches()` helper and the same RFC 6125
matching semantics. A bug fix in one module must be replicated in the other.

**Recommendation:** Extract common matching logic so both call sites share one
implementation, or have the verify module construct a `CertificateInfo` for
the leaf and delegate to the check module.

---

### 27. `find_system_ca_bundle()` duplicates path discovery from `TrustStore::system()`

**Severity:** Low (redundancy)

Both `TrustStore::system()` (verify.rs:183–186) and `find_system_ca_bundle()`
(verify.rs:993–998) maintain the same list of 4 fallback CA bundle paths:

```
/etc/ssl/certs/ca-certificates.crt
/etc/pki/tls/certs/ca-bundle.crt
/etc/ssl/ca-bundle.pem
/etc/ssl/cert.pem
```

`find_system_ca_bundle()` is exported in `lib.rs` but not used by the CLI tool.
If a new path needs to be added, it must be updated in both places.

**Recommendation:** Extract the path list to a constant and have
`TrustStore::system()` call `find_system_ca_bundle()` for path discovery.

---

### 28. `serial_compact()` is unused dead code

**Severity:** Low

`CertificateInfo::serial_compact()` is defined at `fields.rs:230` but never
called anywhere in the codebase (not by the library, the CLI, or any tests).

**Recommendation:** Remove or mark as `#[allow(dead_code)]` if intended for
future public API use.

---

### 29. Repeated `build_dn(x509.subject()).to_oneline()` pattern in `verify.rs`

**Severity:** Low (performance)

The expression `crate::parser::build_dn(x509.subject()).to_oneline()` appears
16 times in `verify_chain_with_options()`. Each call re-traverses the raw ASN.1
DN structure, builds a `DistinguishedName` with string allocations, then
formats it. For a chain of N certificates, this is called O(N) times per
verification check (time validity, basic constraints, critical extensions,
duplicate extensions, Name Constraints, signatures, etc.).

**Recommendation:** Pre-compute subject strings once per certificate after
parsing the chain, storing them alongside the parsed certificates.

---

### 30. `format_crl_reason()` relies on fragile Debug string matching

**Severity:** Medium (correctness risk)

`format_crl_reason()` (verify.rs:1423) uses `format!("{:?}", rc)` to get the
Debug representation of a `ReasonCode`, then matches with `.contains()` checks
(e.g., `debug.contains("KeyCompromise")`). If the upstream `x509-parser` crate
changes its `Debug` formatting (e.g., adds prefixes, changes casing, or wraps
in an enum variant name), all reason codes would silently fall back to
`"unspecified"`.

**Recommendation:** Match on the underlying numeric value of the reason code
if the x509-parser API supports it, or use a more stable API surface.

---

### 31. No file size limit for disk file reads

**Severity:** Medium (security)

`read_input()` (main.rs:275) correctly limits stdin reads to 10 MiB, but
`std::fs::read()` on disk files has no size limit. A file path pointing to a
very large file (or a special device file on Linux like `/dev/zero`) could cause
unbounded memory allocation.

**Recommendation:** Add a file size check (e.g., via `std::fs::metadata()`)
before reading, or use a bounded read similar to the stdin path.

---

### 32. IPv6 formatting duplicated between `parser.rs` and `check.rs`

**Severity:** Low (DRY violation)

Both `parser.rs::format_ip_bytes()` (line 518) and `check.rs::normalize_ip()`
(line 90) format IPv6 addresses as uppercase hex segments without `::`
compression. They produce identical output but implement the formatting
independently.

**Recommendation:** Extract a shared `format_ipv6_expanded()` utility in
`util.rs` and call it from both locations.

---

### 33. `TrustStore::add_pem_directory()` uses overly broad filename matching

**Severity:** Low (correctness)

The hashed certificate file detection at `verify.rs:300`:

```rust
name.chars().last().is_some_and(|c| c.is_ascii_digit())
```

matches any filename ending in a digit, not just OpenSSL hash-linked files.
OpenSSL's hash format is `XXXXXXXX.N` (8 hex chars, dot, single digit), but
this pattern also matches files like `README2`, `backup7`, or `data123`.

**Recommendation:** Use a more specific pattern, such as checking that the
extension is a single digit character (e.g., `ext.len() == 1 && ext.chars()
.next().is_some_and(|c| c.is_ascii_digit())`).

---

### 34. Inconsistent cert file extension filtering across trust store methods

**Severity:** Low (inconsistency)

Three places filter certificate files by extension with different rules:

| Location | Extensions | Case-sensitive |
|---|---|---|
| `TrustStore::system()` dir scan (verify.rs:211) | `.pem`, `.crt` | Yes |
| `TrustStore::add_pem_directory()` (verify.rs:297–300) | `.pem`, `.crt`, `.cer`, digit-ending | Yes |
| `main.rs::is_cert_file()` (main.rs:328) | `.pem`, `.der`, `.crt`, `.cer` | No |

The system trust store dir scan omits `.cer` files that `add_pem_directory()`
would accept. All trust store methods use case-sensitive matching while the
CLI uses case-insensitive.

**Recommendation:** Unify the extension matching logic, ideally sharing a
single function or constant for the accepted extensions.

---

### 35. `verify_chain_with_options()` is ~460 lines and could be decomposed

**Severity:** Low (readability / maintainability)

`verify_chain_with_options()` (verify.rs:437–902) is a single function spanning
~460 lines with 15+ distinct verification checks. This makes it difficult to
review, test individual checks in isolation, or modify one check without risk
of affecting others.

**Recommendation:** Extract logically distinct checks into helper functions
(e.g., `check_time_validity()`, `check_basic_constraints()`,
`check_critical_extensions()`, `check_duplicate_extensions()`,
`check_trust_anchoring()`, `check_name_constraints_chain()`,
`check_key_cert_sign()`, `check_crl_chain()`).
