package com.github.jrepp.gcid;

import java.math.BigInteger;

/** Authenticated GCIDv2 plaintext. */
public record DecodedGcid(
        String prefix,
        long sequence,
        LocationPartition location,
        byte[] header,
        int keyId) {
    public DecodedGcid {
        header = header.clone();
    }

    @Override
    public byte[] header() {
        return header.clone();
    }

    public String unsignedSequenceString() {
        return Long.toUnsignedString(sequence);
    }

    public BigInteger unsignedSequence() {
        return new BigInteger(1, new byte[] {
                (byte) (sequence >>> 56),
                (byte) (sequence >>> 48),
                (byte) (sequence >>> 40),
                (byte) (sequence >>> 32),
                (byte) (sequence >>> 24),
                (byte) (sequence >>> 16),
                (byte) (sequence >>> 8),
                (byte) sequence
        });
    }
}
