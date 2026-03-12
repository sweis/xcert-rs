# cargo-mutants Analysis

This document summarizes the results of running [cargo-mutants](https://mutants.rs/)
against this workspace. Mutation testing introduces small, deliberate bugs
("mutants") into the source code and verifies that at least one test catches
each one. A **missed** mutant means the change went undetected — the tests
passed even though the code was wrong — which indicates a gap in test coverage.

## Summary

```
788 mutants tested: 367 missed, 389 caught, 30 unviable, 2 timeouts
```

| Crate        | Missed | Caught | Score  |
| ------------ | -----: | -----: | -----: |
| `xcert-lib`  |    257 |   ~389 |  ~60%  |
| `xcert` (bin)|    110 |      0 |   ~0%  |

The CLI binary (`xcert/src/main.rs`) is effectively untested end-to-end —
nearly every viable mutant in `main.rs` survives. In `xcert-lib`, the
individual parsing and utility functions are well-covered, but **the
verification pipeline is not**: most individual `check_*` steps can be
deleted entirely without any test noticing.

## How to reproduce

```sh
cargo install cargo-mutants --locked
cargo mutants --no-shuffle
# Results are written to mutants.out/{missed,caught,unviable,timeout}.txt
```

## Missed-mutant distribution (`xcert-lib`)

| File                               | Missed |
| ---------------------------------- | -----: |
| `src/verify/checks.rs`             |     62 |
| `src/verify/webpki.rs`             |     51 |
| `src/verify/constraints.rs`        |     36 |
| `src/fields.rs`                    |     31 |
| `src/verify/crl.rs`                |     17 |
| `src/parser.rs`                    |     17 |
| `src/verify/trust_store.rs`        |     11 |
| `src/verify/mod.rs`                |     10 |
| `src/verify/helpers.rs`            |      7 |
| `src/display.rs`                   |      7 |
| `src/check.rs`                     |      6 |
| `src/verify/chain.rs`              |      2 |

---

## CRITICAL: Verification pipeline gaps

### Entire check functions can be deleted

These functions can be replaced with a no-op (`()`) and **all tests still pass**.
This means no integration test constructs a chain that *fails* because of the
condition being checked — the test suite only covers the happy path.

| Function                                | Location                                | What it's supposed to catch |
| --------------------------------------- | --------------------------------------- | --------------------------- |
| `check_chain_time_validity`             | `verify/checks.rs:26`                   | expired / not-yet-valid certs in chain |
| `check_chain_basic_constraints`         | `verify/checks.rs:51`                   | non-CA certs used as issuers, pathLen violations |
| `check_chain_critical_extensions`       | `verify/checks.rs:100`                  | unrecognized critical extensions |
| `check_chain_duplicate_extensions`      | `verify/checks.rs:120`                  | RFC 5280 §4.2 duplicate-extension violations |
| `check_chain_name_constraint_placement` | `verify/checks.rs:142`                  | NC on leaf / NC not marked critical |
| `check_chain_name_constraints`          | `verify/checks.rs:171`                  | chain-wide Name Constraint enforcement |
| `check_chain_key_cert_sign`             | `verify/checks.rs:203`                  | CA certs missing keyCertSign |
| `check_chain_rfc5280_strict`            | `verify/checks.rs:223`                  | AKI/SKI placement, serial limits, critical-bit rules |
| `check_crl_strict`                      | `verify/checks.rs:696`                  | CRL Number extension presence/criticality |
| `check_webpki_policy`                   | `verify/webpki.rs:17`                   | **all** CABF Baseline Requirements checks |
| `webpki_check_root_aki`                 | `verify/webpki.rs:295`                  | root AKI-vs-SKI consistency |

> **Note** — Some verification tests do exist (`tests/integration.rs` has a
> `verification` module and `name_constraints`/`crl_revocation` modules), but
> they share one root cause: the "bad" test fixtures are **bad in multiple
> ways at once**. For example, a chain that is rejected because of a trust-store
> miss will still be rejected even if time-validity checking is disabled, so
> deleting `check_chain_time_validity` goes unnoticed. Each negative test
> should isolate exactly *one* failure mode.

### Boolean helpers that can be hard-coded

| Function                 | Location                        | Surviving mutation     | Implication |
| ------------------------ | ------------------------------- | ---------------------- | ----------- |
| `ip_matches_constraint`  | `verify/constraints.rs:262`     | always `true` / `false`| IP Name Constraints are effectively untested |
| `email_matches_constraint`| `verify/constraints.rs:232`    | always `true`          | email NC rejection never exercised |
| `is_certificate_chain`   | `verify/mod.rs:212`             | always `true` / `false`| chain-vs-bundle heuristic untested |
| `is_known_extension`     | `verify/helpers.rs:166`         | always `true`          | unknown-critical-extension check is dead in tests |
| `is_single_label_tld`    | `verify/webpki.rs:284`          | always `true` / `false`| wildcard-on-TLD check untested |
| `check_weak_crypto`      | `verify/webpki.rs:213`          | always `None`          | SHA-1 / weak-RSA / P-192 detection untested |
| `is_pem_cert_file`       | `verify/trust_store.rs:27`      | always `true`          | trust-store directory filter untested |
| `check_email`            | `check.rs:65`                   | always `false`         | no test asserts a *matching* email |
| `is_self_issued`         | `verify/helpers.rs:16`          | `==` → `!=`            | self-issued exemption logic untested |

### Other high-value verify findings

- `verify_trust_anchoring` (`checks.rs:408`) — `is_self_signed` check of
  `subject == issuer && sig_ok` can have `&&` → `||` without test failure.
- `check_leaf_purpose` (`checks.rs:607–616`) — the EKU match arms for
  `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`,
  `ocspSigning`, and `anyEKU` are individually deletable. Only `serverAuth`
  is exercised.
- `check_leaf_hostname` (`checks.rs:642`) — the WebPKI-mode CN-fallback
  guard (`policy != WebPki`) is never exercised.
- `check_trusted_root` (`checks.rs:474–573`) — root time-validity boundaries,
  root SKI check, and the root-NC self-issued exemption all survive operator
  flips; no test creates a root that violates these.
- `check_name_constraints` (`constraints.rs:78–188`) — the DNS, email, and
  IP match arms in **both** the excluded-subtree loop and the permitted-subtree
  loop are individually deletable. DNS is slightly covered, but email and IP
  constraint processing is untested.
- `check_crl_revocation` (`crl.rs:87,91`) — `thisUpdate` / `nextUpdate`
  boundary comparisons survive off-by-one flips (`<` → `<=`, `>` → `>=`).

---

## HIGH: Untested public API surface

These public convenience methods on `CertificateInfo` have **no callers in
the test suite** and every mutation survives:

| Method          | Location            | Surviving mutations |
| --------------- | ------------------- | ------------------- |
| `curve()`       | `fields.rs:365`     | `None`, `Some("")`, `Some("xyzzy")` |
| `dns_names()`   | `fields.rs:370`     | `vec![]`, `vec![""]`, `vec!["xyzzy"]`, delete DNS arm |
| `ip_addresses()`| `fields.rs:381`     | `vec![]`, `vec![""]`, `vec!["xyzzy"]`, delete IP arm |

Additionally, `CertificateInfo::emails()` (`fields.rs:300`) — the
`key == "emailAddress" || key == "Email"` key check can become `&&` (which
is always false) without failure: no fixture has an emailAddress in the
subject DN.

---

## MEDIUM: Formatting / display

| Finding | Location | Details |
| ------- | -------- | ------- |
| `DistinguishedName::to_oneline` escaping | `fields.rs:95–97` | the `\\`, `,`, `=` escape branches are all deletable — no fixture has DN components containing those characters |
| `DistinguishedName::to_oneline` separator | `fields.rs:88` | `if i > 0` can become `>=` or `==` — tests don't assert exact separator placement |
| `SanEntry` Display impl | `fields.rs:183` | never called by any test (tests use `Debug` / direct field access) |
| `DateTime::to_openssl` months | `fields.rs:218–229` | every month arm (1–12) is individually deletable — test certificates only cover a few months |
| `VerificationResult` Display impl | `verify/mod.rs:73` | error-message inclusion condition (`!is_valid && !errors.is_empty()`) untested |
| `format_crl_reason` | `verify/crl.rs:41–52` | every reason-code arm is deletable — tests don't assert the reason string |
| `extract_serial_hex` | `verify/helpers.rs:154` | can return `""` or `"xyzzy"` — `ChainCertInfo.serial` is never asserted on |
| `extract_short_name` O/OU fallback | `verify/helpers.rs:130,141` | no cert without a CN is used, so the Organization / OU fallback paths are dead in tests |

### Display module (`display.rs`)

Seven mutants survive, all low-severity: the `colors::boolean` / `colors::number`
helpers, and two conditions that control optional output:

- `display.rs:166` — `if show_all && !cert.signature_hex.is_empty()` — no test
  calls `display_text(_, true)`, so the `show_all` branch is dead.
- `display.rs:319` — the `hex.len() > 40` truncation suffix for `Raw`
  extensions is never reached.

---

## MEDIUM: Parser edge cases

| Finding | Location | Details |
| ------- | -------- | ------- |
| Trailing-data handling | `parser.rs:61` | `input.len() - remaining.len()` can become `+` — tests never feed DER with trailing bytes, so `cert_len` is always `input.len()` and the mutation is masked |
| P-521 key-size mapping | `parser.rs:191` | the `"P-521" => 521` arm is deletable — no P-521 test certificate |
| RSA leading-zero strip | `parser.rs:229` | the `!rest.is_empty()` guard for stripping a single leading `0x00` off the modulus can be inverted — tests don't compare modulus bit-length precisely |
| `der_wrap` length encoding | `parser.rs:302–322` | the short/1-byte/2-byte/3-byte length branch selectors all survive off-by-one flips, and the `>> 8` / `>> 16` shifts can become `<<`. Public keys in test fixtures fall into one length class, so only one branch is exercised |
| `eku_oid_to_name` | `parser.rs:509` | can return `""` / `"xyzzy"` — uncommon EKU names (IPSec, SGC) are not in any test fixture |
| SKI / AKI extension parsing | `parser.rs:410,413` | match arms are deletable — tests never assert on the parsed `SubjectKeyIdentifier` / `AuthorityKeyIdentifier` *value*, only that the extension is present |

---

## MEDIUM: `check_expiry` boundary conditions

`check.rs` — five off-by-one mutations survive in `check_expiry`:

- line 22: `not_before > now` can become `>=` or `==` (not-yet-valid boundary)
- line 29: `not_after < 0` can become `<=` or `==` (pre-epoch edge)
- line 33: `(not_after as u64) > deadline` can become `>=` (expiry boundary)

All three boundary conditions — "becomes valid right now", "expires right
now", "epoch zero" — lack test coverage.

---

## LOW: System-environment dependent

| Function | Location | Reason surviving |
| -------- | -------- | ---------------- |
| `TrustStore::system` bundle loading | `trust_store.rs:84,106` | depends on host filesystem; no test mocks `/etc/ssl` paths |
| `find_system_ca_bundle` | `trust_store.rs:241` | same — not easily unit-testable without filesystem control |

These are expected gaps; they depend on the machine's CA-bundle layout.

---

## Timeouts (infinite loops)

Two mutants caused the test suite to hang:

```
xcert-lib/src/util.rs:29:15: replace < with <= in base64_wrap
xcert-lib/src/util.rs:33:24: replace + with *  in base64_wrap
```

Both turn the `while pos < encoded.len()` line-wrapping loop into an infinite
loop. These aren't test gaps — they're a natural consequence of mutation
testing. (They can be suppressed with `#[cfg_attr(test, mutants::skip)]` on
`base64_wrap` or an `.cargo/mutants.toml` exclusion if desired.)

---

## CLI binary (`xcert/src/main.rs`) — 110 survivors

Every testable mutant in the binary survives. Representative samples:

- All `colors::*` functions can return `Default::default()`
- `read_input`, `infer_format`, `extract_field_value`, `format_field_colored`,
  `run_batch`, `print_verify_result`, and the top-level `run` / `main`
  themselves can all be replaced with trivial bodies
- Every arithmetic operator (`+=`, `*`, `>`, `&&`, `!`) in `run()` survives
  flipping

The existing unit tests in `main.rs` (36 `#[test]` functions) exercise
individual helpers but don't invoke the top-level command dispatch. No
`assert_cmd`-style integration tests exist.

---

## Recommendations (prioritized)

1. **Add per-check negative tests for `verify/checks.rs`.** For each
   `check_chain_*` function, add one chain fixture that fails *only* because
   of that check and assert the expected error string. This is the
   highest-value, highest-severity gap — each check is a security boundary.

2. **Unit-test Name Constraint helpers directly.** Add `#[cfg(test)] mod tests`
   inside `verify/constraints.rs` with cases covering `ip_matches_constraint`,
   `email_matches_constraint`, and `dns_name_matches_constraint` across
   match/no-match/boundary inputs.

3. **Add WebPKI-policy negative tests.** The entire `check_webpki_policy`
   function (51 mutants) is a no-op to the test suite. Create chains that
   violate each CABF rule in isolation.

4. **Exercise the convenience API.** Cover `curve()`, `dns_names()`,
   `ip_addresses()`, and a `check_email` positive case — a few lines each.

5. **Add DN-escaping tests.** Use a synthetic `DistinguishedName` with
   `,` / `=` / `\` in component values.

6. **Add a table-driven `DateTime::to_openssl` test** that iterates timestamps
   covering all twelve months.

7. **Consider a `.cargo/mutants.toml`** to skip the CLI colors module,
   `base64_wrap` (timeouts), and `TrustStore::system` / `find_system_ca_bundle`
   so future runs are cleaner.
