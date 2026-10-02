# GCID Roadmap

**Status: in progress.** The GCIDv2 format and its SDKs exist, but the
specification and SDKs are being hardened before wider adoption. No new
SDKs will be started until the foundation items (F1 to F4) are complete.

Work is delivered as small, independently reviewable pull requests, one
per item below. Each item lists its scope and the spec section it
implements. Items marked **Draft** in `gcid-format.md` track this list.

Status values: `todo`, `in progress`, `done`.

## Foundation

| ID | Item | Scope | Status |
| --- | --- | --- | --- |
| F0 | Spec revision | Trust model, key rotation and canonical form, mandatory location check, fail-closed key, opt-in v1, prefix restriction, conformance section, status and dates cleanup | in progress |
| F1 | Shared conformance vectors | One JSON file of positive and negative vectors in the repo; loaded by every SDK's tests in place of inline tables | todo |
| F2 | Audited or verified AES-GCM-SIV | Run RFC 8452 known-answer tests against the Go and Java implementations; prefer audited libraries where available | todo |
| F3 | Fail-closed key configuration | Python: remove built-in default key and default v1 HMAC key; require explicit key or explicit dev mode. Check Go, Rust, Java for equivalents | todo |
| F4 | Explicit location checking | All SDK decode APIs require an expected location or an explicit any-location opt-out | todo |

## Hardening

| ID | Item | Scope | Status |
| --- | --- | --- | --- |
| H1 | Opt-in GCIDv1 acceptance | Python decoders reject v1 unless legacy acceptance is enabled | todo |
| H2 | Prefix restriction | Enforce lowercase letters, digits, and hyphen in encoders and decoders across all SDKs | todo |
| H3 | Canonical-form helpers | SDK helper to compare identifiers by decoded `(location, sequence)`, and guidance in SDK READMEs | todo |
| H4 | Per-key volume bound | Derive and document the safe encoding volume per key from the RFC 8452 analysis; state it in the spec | todo |

## Design questions

These need a decision before any spec change.

| ID | Question | Status |
| --- | --- | --- |
| D1 | Compact suite with a truncated tag (shorter identifiers) at an explicitly stated security level: worth defining? | todo |
| D2 | Per-location or per-tenant key derivation mapped onto Key ID, for deployments that need key separation inside one trust domain | todo |
| D3 | Shared prefix registry versus application-local prefixes | todo |

## After the foundation

New language SDKs resume once F1 to F4 are done. New SDKs must load the
shared vectors from F1 and pass the RFC 8452 known-answer tests if they
ship their own AES-GCM-SIV.
