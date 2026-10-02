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
| H2 | Prefix restriction | Enforce lowercase letters and digits in encoders and decoders across all SDKs | todo |
| H3 | Canonical-form helpers | SDK helper to compare identifiers by decoded `(location, sequence)`, and guidance in SDK READMEs | todo |
| H4 | Per-key volume bound | Derive and document the safe encoding volume per key from the RFC 8452 analysis; state it in the spec | todo |

## Scoped keys

Depends on F1. Design is in [proposal-scoped-keys.md](proposal-scoped-keys.md).

| ID | Item | Scope | Status |
| --- | --- | --- | --- |
| S1 | Spec for suite 0x02 | Scope-derived keys, rotation rules, vectors | todo |
| S2 | Scoped shared vectors | Positive plus wrong-scope and wrong-generation negatives | todo |
| S3 | Python reference | Scope-aware keyring and mandatory scope on decode | todo |
| S4 | Other SDKs | Rust, Go, Java after S2 | todo |
| S5 | Gateway routing | Suite 0x03: masked route field, routing key, gateway and backend verification, vectors | todo |

## Design questions

These need a decision before any spec change.

| ID | Question | Status |
| --- | --- | --- |
| D1 | Compact suite with a truncated tag (shorter identifiers) at an explicitly stated security level: worth defining? | todo |
| D2 | Per-tenant key derivation and stable IDs across rotation: see [proposal-scoped-keys.md](proposal-scoped-keys.md) | in progress |
| D3 | Shared prefix registry versus application-local prefixes | todo |

## After the foundation

New language SDKs resume once F1 to F4 are done. New SDKs must load the
shared vectors from F1 and pass the RFC 8452 known-answer tests if they
ship their own AES-GCM-SIV.
