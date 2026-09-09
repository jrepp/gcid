GCID
===

Global, Cryptographic, Identifiers
====

Quick examples
=====

```python
from gcid import registry, typed_id
from gcid.gcid import id_to_db_seq

ids = registry(profile="prf", asset="asset")

profile_id = ids.profile(123)
asset_id = ids.asset.from_seq(456)

str(profile_id)
# "prf_QBt6L5GZA4ob6M8wjQ5MWtgochh"

profile_id.seq
# 123

str(asset_id)
# "asset_GLCN4aqgfwoCQT4hcKShEcgFyXw"

ids.asset.to_seq(asset_id)
# 456
```

IDs can also carry a 7-byte location partition inside the encrypted payload.
The public string still only exposes the type prefix and ciphertext:

```python
RegionalAssetId = typed_id("asset", "asset", location=42)

regional_asset_id = RegionalAssetId(123)
str(regional_asset_id)
# "asset_43XfxRWqPm4Tu4iYuGbt6BawSD4h"

regional_asset_id.seq
# 123

regional_asset_id.location_partition.hex()
# "0000000000002a"

id_to_db_seq(regional_asset_id, RegionalAssetId).location.hex()
# "0000000000002a"
```

Conversion benchmark
=====

Run the local benchmark to estimate conversion costs on your machine:

```sh
uv run bench
```

For a faster smoke run:

```sh
GCID_BENCH_N=10000 uv run bench
```

To include cProfile output for the conversion workload:

```sh
GCID_BENCH_N=10000 GCID_BENCH_PROFILE=1 uv run bench
```

The benchmark reports raw encode/decode costs, typed ID construction and `.seq`
access, pydantic model validation costs, and base58-only encode/decode costs in
microseconds per operation.

Recent local profile-guided optimization results, measured with
`GCID_BENCH_N=50000`:

| Operation | Before | After |
| --- | ---: | ---: |
| `seq_to_id` | 5.744 us/op | 5.667 us/op |
| `id_to_seq` | 7.062 us/op | 6.316 us/op |
| typed ID from seq | 13.668 us/op | 6.713 us/op |
| typed ID `.seq` | 7.383 us/op | 0.021 us/op |
| pydantic validation | 23.302 us/op | 16.281 us/op string / 7.625 us/op typed |

The post-optimization profile shows the remaining dominant costs are base58
encoding/decoding, pydantic validation, and cryptography context creation. The
benchmark also reports base58-only costs; in the same run they were about
2.998 us/op for encode and 3.419 us/op for decode.

Crypto validation
=====

GCIDv2 stores a clear binary header in the Base58 payload, then encrypts the
location partition and sequence number with AES-256-GCM-SIV. The visible type
prefix and binary header are authenticated as associated data before decoded
values are trusted.

```text
Encode

  type prefix      header        location      database seq
  "asset"          02 01 01 00   00..2a        123
      |              |             |            |
      +--------------+-------------+------------+
                         |
                         v
             AEAD associated data: prefix + header
                         |
                         v
                  AES-256-GCM-SIV encrypt
                         |
                         v
             +-- header[4] --+-- ciphertext --+-- tag[16] --+
                         |
                         v
                    base58 encode
                         |
                         v
      "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"


Decode / validate

  "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"
                         |
                         v
                 split prefix + base58 body
                         |
                         v
                   parse clear header
                         |
                         v
             authenticate prefix + header + payload
                         |
              +----------+----------+
              |                     |
              v                     v
            reject         AES-256-GCM-SIV decrypt
                                    |
                                    v
                              location, seq
```


Global 
=====

Identifiers contain internal location tagging information that can
be used in a federated system to locate objects globally while
maintaining private internal number spaces.


Cryptographic
=====

Identifiers can be reversed to provide metadata such as row number
and shard without exposing this information to external observers.


Identifiers
=====

Strings that can be used with APIs such as is seen in APIs from Stripe, et al.


Typed IDs
=====

Applications can define their own ID vocabulary once and use those types directly:

```python
from gcid import registry

ids = registry(profile="prf", asset="asset")

profile_id = ids.profile(123)
asset_id = ids.asset.from_seq(456)

str(profile_id)
profile_id.seq
ids.asset.to_seq(asset_id)
```

Typed IDs are string subclasses, so they can be returned directly from API models
while still validating that the prefix and encrypted payload match the expected
type.


Pydantic
=====

Typed IDs validate natively in pydantic models:

```python
from pydantic import BaseModel

from gcid import registry

ids = registry(profile="prf", asset="asset")


class Asset(BaseModel):
    id: ids.asset
    owner_id: ids.profile


asset = Asset(id="asset_...", owner_id="prf_...")
asset.id.seq
asset.model_dump()
```

Pydantic validation accepts GCID strings by default. Direct construction accepts
integers for internal use, e.g. `ids.asset(123)`, but pydantic fields reject raw
sequence numbers unless the type is created with `accept_seq_in_pydantic=True`.


Releases
=====

This repository hosts several independently versioned language packages:

| Package | Path | Release tag prefix | Consumed via |
| --- | --- | --- | --- |
| Python `gcid` | repo root | `python/vX.Y.Z` | PyPI (`pip install gcid`) |
| Go `gcid` | `go/gcid` | `go/gcid/vX.Y.Z` | Go module proxy (`go get github.com/jrepp/gcid/go/gcid@vX.Y.Z`) |
| Rust `gcid` crate | `rust/gcid` | `rust/gcid/vX.Y.Z` | crates.io |
| Java `gcid` library | `java/gcid` | `java/gcid/vX.Y.Z` | Maven Central |

[Release Please](https://github.com/googleapis/release-please) reads
[conventional commits](https://www.conventionalcommits.org/) on `main` and
opens a release pull request that bumps versions, updates changelogs, and,
once merged, creates a prefixed tag and GitHub release for each changed
package. Commit messages that only affect one package should be scoped
accordingly (for example `feat(go): ...`) so each package is versioned on its
own cadence.

When a `python/*` release is cut, the release workflow builds the package and
publishes it to PyPI. Go packages need no upload: a `go/gcid/vX.Y.Z` tag is
resolved directly by the Go module proxy. crates.io and Maven Central uploads
for the Rust and Java packages are wired the same way once their registry
publishing is configured.
