# Proposal: Scoped Keys for Stable IDs and Tenant Verification

**Status:** proposal, not yet part of the specification. Tracked as
roadmap item S1 in [ROADMAP.md](ROADMAP.md).

## Problems

1. **Rotation changes IDs.** GCIDv2 is deterministic per key, so changing
   the emitting key changes the string for every row. The current spec
   can only say "compare decoded values".
2. **Tenant checks are advisory.** Every decoder holds the one key, so it
   can decode and forge IDs for every tenant. The location comparison is
   a check the caller can forget or skip.

## Proposal in one paragraph

Add suite `0x02`: the same AES-256-GCM-SIV and the same wire layout, but
the encryption key is derived per **scope** (tenant) from a **generation
key** selected by the existing Key ID octet. A tenant-confined service
holds only its own scope key, so another tenant's ID fails authentication
rather than failing a comparison. Generation keys are independent random
keys, so the secret that protects them can be rotated without changing a
single ID.

## Design

### Key hierarchy

```text
KEK (in KMS, rotates freely)
  wraps -> generation key K_g   random 256-bit, selected by Key ID
              derives -> scope key K_s   per tenant, one-way
```

```text
K_s = HKDF-SHA256(
        ikm  = K_g,
        salt = empty,
        info = "GCIDv2/scope" || 0x00 || key_id (1) ||
               len(scope) (2, big endian) || scope,
        L    = 32)
```

`scope` is an opaque octet string of at most 255 octets chosen by the
deployment, such as a fixed-width binary tenant ID. Suite `0x02` uses
`K_s` exactly where suite `0x01` uses the configured key. Nonce, header
layout, plaintext, tag and associated data are unchanged, so the payload
stays 35 octets and no wire bytes are added.

The scope is not on the wire. The caller supplies it from authenticated
request context, and a wrong scope derives a wrong key.

### What rotation means

| Event | Effect on existing IDs | Mechanism |
| --- | --- | --- |
| KEK rotation | None | Re-wrap `K_g`; `K_g` itself is unchanged |
| New generation | None | New rows pin the new Key ID; old rows keep theirs |
| Scope key compromise | That scope only | Retire `(key_id, scope)`, re-mint that tenant's rows under a new generation, keep an alias window |
| Generation key compromise | All scopes under that generation | Same, wider blast radius |

Stability rule: the string is a pure function of
`(prefix, scope, key_id, location, sequence)`. A row therefore **pins its
Key ID at mint time**. Either store the Key ID with the row (one octet),
or, for monotonic sequences, keep a small watermark table mapping
sequence ranges to Key IDs. The string never depends on which generation
is currently emitting.

IDs change only on compromise, which is the one case where they should.
A retired key is decoded only through an explicit alias path that decodes
with the old key and re-encodes with the new one.

Generation keys must not be derived from a master secret. If they were,
rotating the master would change `K_g` and so every ID.

### Tenant verification

- **Cryptographic isolation.** A tenant-confined service is provisioned
  with `K_s` only. HKDF is one-way, so it cannot derive sibling scopes
  and cannot decode or forge another tenant's IDs.
- **No oracle.** An ID from another tenant fails authentication exactly
  like a forged ID. Callers learn nothing about which tenant owns it.
- **Required scope in the API.** Decoders take a mandatory scope argument.
  There is no unscoped decode in suite `0x02`, so the check cannot be
  skipped. This replaces the explicit-location requirement for tenancy.
- **Location keeps its job.** The 56-bit location remains for shard or
  region routing and is still verified when an expected value is given.
- **No cross-tenant equality leak.** The same `(location, sequence)`
  under two scopes yields unrelated strings.
- **Smaller blast radius per key.** Each scope key encodes only one
  tenant's rows, which helps the per-key volume bound (H4).

### Compatibility

Decoders dispatch on the Suite octet. A suite `0x01` decoder rejects
suite `0x02` before decryption, as the spec already requires. Suite
`0x01` stays valid for single-tenant deployments, and no migration is
forced.

### Costs and limits

- Suite `0x02` cannot be routed from an ID alone. Gateways must route on
  authenticated context, or use the routing suite below.
- A resource shared between tenants is minted under its owner's scope.
  The other tenant cannot decode it and must resolve it through the owner.
- A deployment needs a key service that hands out `K_s` and holds `K_g`.
  This is operational work that suite `0x01` did not need.
- Compromise recovery still changes strings for the affected scope.

## Extension: gateway routing (suite 0x03)

A gateway that receives an ID with no other context needs to find the
owning tenant or backend. Suite `0x03` adds a masked route field and a
second key derived from the same generation key, so the ID becomes a
**composite**: a routing key that gateways hold, and a scope key that
only backends hold.

```text
K_r = HKDF-SHA256(ikm = K_g, salt = empty,
                  info = "GCIDv2/route" || 0x00 || key_id, L = 32)
```

`K_s` is derived as before, and HKDF's one-way property keeps `K_r` and
`K_s` independent: holding `K_r` reveals nothing about `K_s` or `K_g`.

### Wire layout

```text
+-----------+-----------+------------------+-----------+
| Header 4  | Route 4   | Ciphertext 15    | Tag 16    |
+-----------+-----------+------------------+-----------+
```

The payload is 39 octets, 4 more than suite `0x02`, about 54 Base58
characters. Header, plaintext, inner AEAD and associated data are exactly
as in suite `0x02`, with `K_s`. Only the Route field is new.

```text
route = rid XOR HMAC-SHA256(K_r, "GCIDv2/route" || 0x00 || prefix ||
                            0x00 || header || tag)[0..4]
```

`rid` is a 32-bit **route identifier** chosen by the deployment. The
tag already depends on the plaintext, so it acts as a synthetic IV for
the mask. The Route field therefore differs for every ID even when `rid`
is the same, so observers cannot group IDs by route.

### Gateway

1. Base58-decode, read the header, and select `K_r` by Key ID.
2. Recompute the mask from the visible prefix, header and tag, and XOR it
   with the Route field to recover `rid`.
3. Look up `rid` in the routing table and forward.

The gateway never holds `K_s` or `K_g`. It cannot decode the location or
sequence, and it cannot mint an ID that a backend will accept. It
routes; it does not authenticate.

### Backend

The backend decodes with `K_s` exactly as in suite `0x02`, and also holds
`K_r` for the generations it serves. Before trusting the ID it MUST
recompute the Route field from its own `rid` set and reject a mismatch.
This keeps one canonical string per row; without it, the 32 route bits
would be malleable.

### Properties

- **Misrouting is harmless.** A forged or altered Route field leads to a
  backend that rejects it. Choose `rid` values from a sparse random
  space so that a random Route field rarely matches a real target and
  the gateway can drop most junk early.
- **No new leak to outsiders.** An outside observer sees no tenant,
  region or route, only the same random-looking payload as before.
- **Gateway sees routing only.** It learns `rid` and which IDs share a
  `rid`, which is its job, and nothing about location or sequence.
- **Tenant verification is unchanged.** The scope key still gates
  decoding, so `rid` is a routing hint and never an authorization.

### Keeping IDs stable

`rid` is baked into the string, so it must name a **logical** target such
as a tenant or cell, never a physical address. The routing table maps
`rid` to the current endpoint, so moving a tenant between backends edits
the table and no ID changes. Splitting or merging logical targets changes
`rid` and therefore IDs, and is treated like a re-mint.

`rid` and scope are independent. When many tenants share a backend, `rid`
names the backend and the scope names the tenant, which the backend
takes from authenticated context.

### Costs

- 4 more octets per ID.
- Gateways and backends need `K_r`, so key distribution has three
  tiers: `K_g` in the key service only, `K_r` to gateways and backends,
  `K_s` to the owning backends.
- A compromised `K_r` exposes routing only and lets an attacker steer
  traffic, but not decode or forge IDs.

## Open questions

1. Canonical scope encoding: fixed-width binary only, or allow strings?
   Recommend fixed-width binary.
2. Pinning: per-row Key ID column versus watermark table. Recommend the
   column, with watermarks documented as an optimization.
3. Alias window mechanics: who publishes retirements, and for how long.
4. Should suite `0x02` become the recommended default once shipped?
5. Route field width: 32 bits as proposed, or 16 for shorter IDs at the
   cost of a denser `rid` space and more junk reaching backends?
6. Should `K_r` be per generation as proposed, or per region so that a
   regional gateway cannot route another region's IDs?

## Delivery

Each step is its own pull request.

1. Spec: define suite `0x02`, derivation, rotation rules, conformance
   vectors (S1).
2. Shared vectors for suite `0x02`, including wrong-scope and
   wrong-generation negatives (extends F1).
3. Python reference implementation with a scope-aware keyring.
4. Suite `0x03` routing: spec, vectors, Python gateway and backend
   reference (S5).
5. Rust, Go and Java after the vectors land.
