# gcid

Idiomatic Rust implementation of the GCIDv2 wire format.

GCIDv2 strings have the shape:

```text
<prefix>_<base58-payload>
```

The Base58 payload contains a clear 4-byte header followed by
AES-256-GCM-SIV ciphertext and a 16-byte authentication tag. The visible
prefix and clear header are authenticated as associated data.

## Usage

```rust
use gcid::GcidCodec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = *b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    let codec = GcidCodec::new(key);

    let id = codec.encode("prf", 123)?;
    assert_eq!(
        id,
        "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ",
    );

    let decoded = codec.decode("prf", &id)?;
    assert_eq!(decoded.sequence, 123);
    assert_eq!(decoded.location_u64(), 0);

    let regional = codec.encode_with_location("asset", 123, 42)?;
    let decoded = codec.decode("asset", &regional)?;
    assert_eq!(decoded.location_u64(), 42);

    Ok(())
}
```

## Development

From this directory:

```sh
cargo test
cargo fmt --check
```

The crate test suite includes the GCIDv2 vectors from
`../../docs/gcid-format.md`.

## Benchmark

Run the local release benchmark:

```sh
GCID_BENCH_N=100000 cargo run --release --example bench
```

Recent local result on Apple Silicon:

```text
Rust GCIDv2 benchmark (100000 operations)
----------------------------------------------------------------
rust encode           4.839 us/op       206655 ops/s
rust decode           5.945 us/op       168206 ops/s
```

The matching Python run from the repository root measured about
`22.041 us/op` for encode and `19.651 us/op` for decode.
