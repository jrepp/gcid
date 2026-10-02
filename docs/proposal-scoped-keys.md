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

- Tenant cannot be read from an ID alone. Gateways must route on
  authenticated context or a hint outside the ID.
- A resource shared between tenants is minted under its owner's scope.
  The other tenant cannot decode it and must resolve it through the owner.
- A deployment needs a key service that hands out `K_s` and holds `K_g`.
  This is operational work that suite `0x01` did not need.
- Compromise recovery still changes strings for the affected scope.

## Open questions

1. Canonical scope encoding: fixed-width binary only, or allow strings?
   Recommend fixed-width binary.
2. Pinning: per-row Key ID column versus watermark table. Recommend the
   column, with watermarks documented as an optimization.
3. Alias window mechanics: who publishes retirements, and for how long.
4. Should suite `0x02` become the recommended default once shipped?

## Delivery

Each step is its own pull request.

1. Spec: define suite `0x02`, derivation, rotation rules, conformance
   vectors (S1).
2. Shared vectors for suite `0x02`, including wrong-scope and
   wrong-generation negatives (extends F1).
3. Python reference implementation with a scope-aware keyring.
4. Rust, Go and Java after the vectors land.
