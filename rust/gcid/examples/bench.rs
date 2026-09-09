use std::time::Instant;

use gcid::{Gcid, GcidCodec};

fn time_ops<F>(label: &str, count: usize, mut f: F)
where
    F: FnMut(),
{
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    let us_per_op = elapsed.as_secs_f64() / count as f64 * 1_000_000.0;
    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    println!("{label:16} {us_per_op:10.3} us/op {ops_per_sec:12.0} ops/s");
}

fn main() {
    let count = std::env::var("GCID_BENCH_N")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000);
    let key = *b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    let codec = GcidCodec::new(key);
    let sequences: Vec<u64> = (1..=count as u64).collect();
    let ids: Vec<Gcid> = sequences
        .iter()
        .map(|sequence| codec.encode("prf", *sequence).unwrap())
        .collect();

    println!("Rust GCIDv2 benchmark ({count} operations)");
    println!("----------------------------------------------------------------");
    time_ops("rust encode", count, || {
        let encoded: Vec<Gcid> = sequences
            .iter()
            .map(|sequence| codec.encode("prf", *sequence).unwrap())
            .collect();
        std::hint::black_box(encoded);
    });
    time_ops("rust decode", count, || {
        let decoded: Vec<u64> = ids
            .iter()
            .map(|id| codec.decode("prf", id).unwrap().sequence)
            .collect();
        std::hint::black_box(decoded);
    });
}
