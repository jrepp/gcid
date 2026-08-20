GCID
===

Global, Cryptographic, Identifiers
====

Quick examples
=====

```python
from gcid import registry, typed_id
from gcid.gcid import IdType, id_to_db_seq, id_to_seq, seq_to_id

ids = registry(profile="prf", asset="asset")

profile_id = ids.profile(123)
asset_id = ids.asset.from_seq(456)

str(profile_id)
# "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ"

profile_id.seq
# 123

str(asset_id)
# "asset_Cbds3PQ1ZC2vzDFLB7qWod4hHnAuFwt4uqFH6NbKL1ZBCvT"

ids.asset.to_seq(asset_id)
# 456
```

IDs can also carry a 7-byte location partition inside the encrypted payload.
The public string still only exposes the type prefix and ciphertext:

```python
RegionalAssetId = typed_id("asset", "asset", location=42)

regional_asset_id = RegionalAssetId(123)
str(regional_asset_id)
# "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"

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

The benchmark reports v2 encode/decode costs, v1 compatibility encode/decode
costs, typed ID construction and `.seq` access, pydantic model validation costs,
and base58-only encode/decode costs in microseconds per operation.

The Rust and Go packages have matching GCIDv2 benchmarks:

```sh
cd rust/gcid
GCID_BENCH_N=100000 cargo run --release --example bench

cd go/gcid
go test -bench=. -benchmem ./...
```

Recent local GCIDv2 encode/decode comparison, measured with
`GCID_BENCH_N=100000` on Apple Silicon:

| Implementation | Encode | Decode |
| --- | ---: | ---: |
| Python | 22.041 us/op | 19.651 us/op |
| Rust release | 4.839 us/op | 5.945 us/op |
| Go 1.26.4 | 10.301 us/op | 13.015 us/op |
| Java 25.0.3 | 10.672 us/op | 10.497 us/op |

On that run, Rust encode was about 4.56x faster than Python and Rust decode was
about 3.31x faster. Go encode was about 2.14x faster than Python and Go decode
was about 1.51x faster. Java encode was about 2.07x faster than Python and Java
decode was about 1.87x faster. Treat these as local ballpark numbers, not
portable guarantees; CPU, JVM warmup, OpenSSL/backend availability, Go/Python
version, and Base58 costs all matter.

V1 migration compatibility
=====

GCIDv2 is the default for all existing constructors:

```python
seq_to_id(IdType.PROFILE, 123)
# "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ"
```

Existing GCIDv1 strings still decode with the same APIs, so services can accept
stored or inbound v1 IDs while emitting v2 for new IDs:

```python
id_to_seq("prf_QBt6L5GZA4ob6M8wjQ5MWtgochh", IdType.PROFILE)
# 123
```

If an older client still requires v1 output during a migration window, opt in
explicitly:

```python
seq_to_id(IdType.PROFILE, 123, format_version=1)
# "prf_QBt6L5GZA4ob6M8wjQ5MWtgochh"

LegacyProfileId = typed_id("profile", "prf", format_version=1)
str(LegacyProfileId(123))
# "prf_QBt6L5GZA4ob6M8wjQ5MWtgochh"
```

Rust implementation
=====

An idiomatic Rust GCIDv2 crate lives in `rust/gcid`. It exposes a `GcidCodec`
for encoding and decoding v2 IDs with the same test vectors as the Python
reference implementation.

```rust
use gcid::GcidCodec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let codec = GcidCodec::new(*b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    let id = codec.encode("prf", 123)?;
    let decoded = codec.decode("prf", &id)?;
    assert_eq!(decoded.sequence, 123);

    Ok(())
}
```

Go implementation
=====

An idiomatic, zero-dependency Go GCIDv2 package lives in `go/gcid`. It exposes
a `Codec`, typed `ID`, `LocationPartition`, and keyring support.

```go
package main

import (
    "fmt"
    "log"

    "github.com/jrepp/gcid/go/gcid"
)

func main() {
    codec, err := gcid.NewCodec([]byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
    if err != nil {
        log.Fatal(err)
    }

    id, err := codec.Encode("prf", 123)
    if err != nil {
        log.Fatal(err)
    }

    decoded, err := codec.DecodeID("prf", id)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(id.String(), decoded.Sequence)
}
```

Java implementation
=====

An idiomatic, dependency-free Java GCIDv2 package lives in `java/gcid`. It uses
the JDK AES primitive and implements the AES-256-GCM-SIV construction required
by GCIDv2.

```java
import com.github.jrepp.gcid.GcidCodec;

final class Example {
    public static void main(String[] args) throws Exception {
        var codec = GcidCodec.create("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes());
        var id = codec.encode("prf", 123);
        var decoded = codec.decode("prf", id);

        System.out.println(id);
        System.out.println(Long.toUnsignedString(decoded.sequence()));
    }
}
```

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
