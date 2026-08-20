package com.github.jrepp.gcid;

public final class GcidBenchmark {
    private static final int DEFAULT_COUNT = 100_000;
    private static final byte[] DEV_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes();

    public static void main(String[] args) throws Exception {
        var count = Integer.parseInt(System.getenv().getOrDefault("GCID_BENCH_N", String.valueOf(DEFAULT_COUNT)));
        var codec = GcidCodec.create(DEV_KEY);
        var ids = new GcidId[count];
        for (int i = 0; i < count; i++) {
            ids[i] = codec.encode("prf", i + 1L);
        }

        System.out.printf("Java GCIDv2 benchmark (%d operations)%n", count);
        System.out.println("----------------------------------------------------------------");
        time("java encode", count, () -> {
            var encoded = new GcidId[count];
            for (int i = 0; i < count; i++) {
                encoded[i] = codec.encode("prf", i + 1L);
            }
            blackhole(encoded);
        });
        time("java decode", count, () -> {
            long sum = 0;
            for (var id : ids) {
                sum += codec.decode("prf", id).sequence();
            }
            blackhole(sum);
        });
    }

    private static void time(String label, int count, ThrowingRunnable runnable) throws Exception {
        var start = System.nanoTime();
        runnable.run();
        var elapsed = System.nanoTime() - start;
        var nsPerOp = (double) elapsed / count;
        var opsPerSec = 1_000_000_000.0 / nsPerOp;
        System.out.printf("%-16s %10.0f ns/op %12.0f ops/s%n", label, nsPerOp, opsPerSec);
    }

    private static volatile Object sink;

    private static void blackhole(Object value) {
        sink = value;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
