# Global Cryptographic Identifier (GCID) Format Version 2

Internet-Draft                                                J. Repp
Intended status: Informational                              GCID Project
Expires: TBD                                                  June 2026


## Abstract

This document specifies GCIDv2, a compact, typed, reversible identifier
format for API resources.  A GCID string contains a visible resource
prefix and a Base58-encoded cryptographic payload.  The payload carries
a self-describing header and an authenticated encrypted body.  The
default payload profile stores a 64-bit sequence number and a 56-bit
location partition while hiding those internal values from external
observers.

GCIDv2 is intentionally distinct from UUIDs, CIDs, Sqids, and bearer
tokens.  It is for systems that need stable public identifiers that are
typed for application routing, reversible by trusted services, compact
enough for API use, and cryptographically protected against tampering.


## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions
of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task
Force (IETF).  Internet-Drafts are draft documents valid for a maximum
of six months and may be updated, replaced, or obsoleted by other
documents at any time.  It is inappropriate to use Internet-Drafts as
reference material or to cite them other than as "work in progress."


## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals,
as shown here.

Prefix:
: A visible ASCII string that identifies the application resource type,
  such as `prf` or `asset`.

Header:
: The cleartext binary metadata at the start of the Base58 payload.  It
  identifies the GCID version, cryptographic suite, payload schema, and
  key identifier.

Payload Profile:
: The binary plaintext schema encrypted inside the GCID payload.  This
  document defines the `seq64-loc56` profile.

Associated Data:
: Cleartext data that is authenticated by the cryptographic suite but
  not encrypted.  GCIDv2 authenticates the visible prefix and binary
  header as associated data.

Location Partition:
: A 56-bit value used to distinguish an internal location, shard,
  region, tenant, or similar partition.

Sequence:
: An unsigned 64-bit integer assigned by the application or database.


## Design Goals

GCIDv2 has the following goals:

* Keep the public string ergonomic: `<prefix> "_" <base58-payload>`.
* Bind the visible prefix cryptographically to the encrypted payload.
* Make version, suite, schema, and key selection available before
  decryption.
* Support deterministic reversible IDs without exposing internal
  sequence or location values.
* Allow future cryptographic suites and payload profiles without
  changing the visible string shape.
* Remain practical to implement across languages using common
  cryptographic libraries.

GCIDv2 does not try to be a general content identifier, bearer token,
authorization credential, or non-reversible random identifier.


## String Format

A GCIDv2 string has two visible components:

```text
<prefix> "_" <base58-payload>
```

The prefix is visible and not encrypted.  It is nevertheless
authenticated as associated data, so changing the visible prefix
invalidates the payload.

GCID strings are ASCII strings.  The prefix component MUST contain at
least one character and MUST NOT contain `_` (U+005F).  Applications MAY
apply additional prefix restrictions.  For broad language and URL
interoperability, applications SHOULD restrict prefixes to lowercase
ASCII letters, digits, and hyphen.

The encoded payload MUST use the Bitcoin Base58 alphabet:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

For the `seq64-loc56` profile with the `AES-256-GCM-SIV` suite, the
encoded payload MUST decode to exactly 35 octets.


## Binary Payload Layout

The Base58 payload is:

```text
+----------------+-----------------------------------------------+
| Header (32)    |        AEAD Ciphertext and Tag (248)          |
+----------------+-----------------------------------------------+
```

The 4-octet header is:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
| Version (8)   | Suite (8)     | Schema (8)    | Key ID (8)    |
+---------------+---------------+---------------+---------------+
```

GCIDv2 defines the following initial code points:

| Field | Value | Meaning |
| --- | ---: | --- |
| Version | `0x02` | GCID format version 2 |
| Suite | `0x01` | AES-256-GCM-SIV deterministic AEAD |
| Schema | `0x01` | `seq64-loc56` payload profile |
| Key ID | `0x00` | Default reference key identifier |

Implementations MUST reject unsupported version, suite, schema, or key
identifier values before decryption.  Implementations SHOULD use the Key
ID to select a configured key.  The Python reference implementation
emits and accepts Key ID `0x00`.


## `seq64-loc56` Payload Profile

The `seq64-loc56` plaintext is 15 octets:

```text
+---------------------------------------------------------------+
|                  Location Partition (56)                      |
+---------------------------------------------------------------+
|                                                               |
|                         Sequence (64)                         |
|                                                               |
+---------------------------------------------------------------+
```

All integer values are encoded in network byte order (big endian).

The location partition MUST be an unsigned 56-bit value.  If no
location partition is supplied, implementations MUST use zero.  The
sequence MUST be an unsigned 64-bit value.


## Cryptographic Suite `0x01`

Suite `0x01` is AES-256-GCM-SIV as specified by [RFC8452], used through
the authenticated encryption with associated data interface described by
[RFC5116].

Implementations compatible with this document MUST use:

* AES-256-GCM-SIV.
* A 32-octet encryption key selected by Key ID.
* A 12-octet nonce containing all zero octets.
* A 16-octet authentication tag.
* Plaintext: the payload profile bytes.
* Associated data:

```text
"GCIDv2" || 0x00 || prefix || 0x00 || header
```

The all-zero nonce is intentional for this deterministic identifier
profile.  AES-GCM-SIV is nonce-misuse resistant and is used here to
avoid the CBC-plus-truncated-MAC construction used by GCIDv1.  The same
key, prefix, header, location, and sequence produce the same GCID.
Systems that require unlinkability between repeated encodings of the
same database row SHOULD use a different payload profile that includes
randomness or SHOULD use a non-reversible identifier format.


## GCID Generation

To generate a GCIDv2 string, an implementation MUST perform the
following steps:

1. Validate that the prefix is non-empty ASCII and does not contain `_`.
2. Select a supported suite, schema, and key identifier.
3. Construct the 4-octet header.
4. Validate and encode the payload profile plaintext.
5. Construct associated data from the domain string, prefix, and header.
6. Encrypt the plaintext with the selected AEAD suite.
7. Concatenate `header || ciphertext_and_tag`.
8. Base58-encode the binary payload.
9. Return `prefix || "_" || encoded_payload`.


## GCID Validation and Decoding

To validate and decode a GCIDv2 string, an implementation MUST perform
the following steps:

1. Verify that the GCID is a string.
2. Split the string on `_`.  The result MUST contain exactly two parts.
3. Verify that the visible prefix matches the expected resource type.
4. Base58-decode the encoded payload.  Invalid Base58 input MUST be
   rejected.
5. Verify that the decoded payload length matches the selected format.
6. Parse the header and reject unsupported version, suite, or schema
   values.
7. Select the configured key using Key ID.
8. Construct associated data from the domain string, visible prefix, and
   header.
9. Decrypt and authenticate the ciphertext.  Authentication failure MUST
   reject the GCID.
10. Parse the payload profile plaintext.
11. If an expected location partition is configured, verify that the
    decoded location partition matches it.
12. Return the decoded sequence and location partition.

Implementations MUST NOT return partial decoded data from malformed or
unauthenticated input.


## ABNF

The following ABNF [RFC5234] describes the textual GCID shape.  It does
not capture the binary payload length requirement, which MUST be checked
after Base58 decoding.

```abnf
gcid           = prefix "_" base58-payload
prefix         = 1*(%x21-5E / %x60-7E)
                 ; visible ASCII except "_"
base58-payload = 1*base58-char
base58-char    = %x31-39 / %x41-48 / %x4A-4E / %x50-5A /
                 %x61-6B / %x6D-7A
                 ; Bitcoin Base58 alphabet
```


## Registered Reference Prefixes

The Python reference package defines the following built-in prefixes:

| Resource Type | Prefix |
| --- | --- |
| Profile | `prf` |
| Organization | `org` |
| Asset | `asset` |
| File | `file` |
| Event | `evt` |
| Topology | `topo` |
| Job Definition | `jobdef` |
| Job | `job` |
| Job Result | `jobres` |
| Reader | `read` |
| Tag | `tag` |

Applications MAY define additional prefixes.  Prefix registries are
application-local unless a future document establishes a shared registry.


## Test Vectors

The following vectors use the Python reference development key:

* AES-256-GCM-SIV key: `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
* Nonce: `000000000000000000000000`
* Header: `02010100`

| Prefix | Location | Sequence | Ciphertext | Tag | GCID |
| --- | ---: | ---: | --- | --- | --- |
| `prf` | 0 | 123 | `619d1d6dc26f2d50845c51ee5b6f37` | `f8015069da306ae7ee323ddcb428c45f` | `prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ` |
| `asset` | 0 | 456 | `be57802f7f0f0123077557a54ea928` | `49ee9bd1fd58fd7476aef836e2d54ff8` | `asset_Cbds3PQ1ZC2vzDFLB7qWod4hHnAuFwt4uqFH6NbKL1ZBCvT` |
| `asset` | 42 | 123 | `1c313f1a04c3c016de1298477fe0b8` | `1f05d8b70283707ad41305890d03d7fe` | `asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M` |
| `prf` | 0 | 0 | `f3e6a0e5334c0076886a9dc80a9d4a` | `b5fb28e63cede5a351e1e72f70b4f0fe` | `prf_Cbds4CmMHP4273kXPwFQ8DQCPu3sd4CSAmhYDA7RzkTEGmb` |
| `prf` | 0 | 18446744073709551615 | `0a4401ea838160882402e258cc8de4` | `3f8c3ad5f654505d698dde38a96175e5` | `prf_Cbdrze8v48sf8q2jPwrCf3TMB4Gs3YiHcnki91GDYsBwmxp` |


## Security Considerations

GCIDv2 confidentiality and integrity depend on the secrecy of the
selected AES-GCM-SIV key.  Deployments MUST NOT use the default
development key in production.

The visible prefix is authenticated as associated data.  Relabeling a
payload from one prefix to another MUST fail authentication.

The `seq64-loc56` profile is deterministic.  Observers cannot recover
the sequence or location values without the key, but they can determine
when the same prefix and payload have been emitted more than once.

Location partitions often encode tenant, region, or shard boundaries.
Multi-tenant services MUST verify the expected location partition from
trusted request or routing context before using the decoded sequence.

Key ID is cleartext and is intended for key lookup only.  It is not an
authorization signal.  Implementations SHOULD support key rotation by
accepting multiple configured keys for decoding and emitting only the
current key for new IDs.

GCIDv2 strings are stable identifiers, not bearer credentials.  Services
MUST perform authorization independently of GCID validation.


## Prior Art and Adoption Notes

GCIDv2 borrows the AEAD interface from [RFC5116], the deterministic and
nonce-misuse-resistant direction from AES-SIV [RFC5297] and
AES-GCM-SIV [RFC8452], and the self-describing identifier lesson from
content identifiers such as CIDs and multibase.  UUIDs [RFC9562] remain
the better default when reversibility and hidden database metadata are
not required.  Sqids and Hashids-style formats are useful for cosmetic
obfuscation, but they are not cryptographic integrity or confidentiality
mechanisms.


## IANA Considerations

This document has no IANA actions.


## References

### Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March
1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC5116] McGrew, D., "An Interface and Algorithms for Authenticated
Encryption", RFC 5116, DOI 10.17487/RFC5116, January 2008,
<https://www.rfc-editor.org/info/rfc5116>.

[RFC5234] Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax
Specifications: ABNF", STD 68, RFC 5234, DOI 10.17487/RFC5234, January
2008, <https://www.rfc-editor.org/info/rfc5234>.

[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
<https://www.rfc-editor.org/info/rfc8174>.

[RFC8452] Gueron, S., Langley, A., and Y. Lindell, "AES-GCM-SIV:
Nonce Misuse-Resistant Authenticated Encryption", RFC 8452,
DOI 10.17487/RFC8452, April 2019,
<https://www.rfc-editor.org/info/rfc8452>.

### Informative References

[RFC5297] Harkins, D., "Synthetic Initialization Vector (SIV)
Authenticated Encryption Using the Advanced Encryption Standard (AES)",
RFC 5297, DOI 10.17487/RFC5297, October 2008,
<https://www.rfc-editor.org/info/rfc5297>.

[RFC9562] Davis, K., Peabody, B., and P. Leach, "Universally Unique
IDentifiers (UUIDs)", RFC 9562, DOI 10.17487/RFC9562, May 2024,
<https://www.rfc-editor.org/info/rfc9562>.

[CID] Multiformats, "Content Identifiers",
<https://github.com/multiformats/cid>.

[MULTIBASE] Multiformats, "Multibase",
<https://github.com/multiformats/multibase>.

[SQIDS] Sqids, "Sqids",
<https://sqids.org/>.


## Acknowledgements

GCIDv2 is based on operational lessons from the Python `gcid` reference
implementation and its GCIDv1 predecessor.
