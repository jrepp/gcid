package com.github.jrepp.gcid;

import java.util.Arrays;

/** The encrypted 56-bit GCID location partition. */
public final class LocationPartition {
    public static final int BYTE_LENGTH = 7;
    public static final LocationPartition ZERO = new LocationPartition(new byte[BYTE_LENGTH]);

    private final byte[] bytes;

    private LocationPartition(byte[] bytes) {
        this.bytes = bytes;
    }

    public static LocationPartition fromBytes(byte[] bytes) {
        if (bytes.length != BYTE_LENGTH) {
            throw new IllegalArgumentException("location must be exactly 7 bytes");
        }
        return new LocationPartition(bytes.clone());
    }

    public static LocationPartition of(byte[] bytes) {
        return fromBytes(bytes);
    }

    public static LocationPartition fromLong(long value) {
        if (value < 0 || value >= (1L << 56)) {
            throw new IllegalArgumentException("location must fit in 56 bits: " + value);
        }
        var bytes = new byte[BYTE_LENGTH];
        for (int i = BYTE_LENGTH - 1; i >= 0; i--) {
            bytes[i] = (byte) value;
            value >>>= 8;
        }
        return new LocationPartition(bytes);
    }

    public static LocationPartition of(long value) {
        return fromLong(value);
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public long asLong() {
        long value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xffL);
        }
        return value;
    }

    byte[] rawBytes() {
        return bytes;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof LocationPartition location && Arrays.equals(bytes, location.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
