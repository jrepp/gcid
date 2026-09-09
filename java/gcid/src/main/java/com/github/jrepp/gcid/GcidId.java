package com.github.jrepp.gcid;

import java.util.Objects;

/** A syntactically validated GCID string. */
public final class GcidId {
    private final String value;
    private final int prefixLength;

    private GcidId(String value, int prefixLength) {
        this.value = value;
        this.prefixLength = prefixLength;
    }

    public static GcidId parse(String value) throws GcidException {
        Objects.requireNonNull(value, "value");
        var parts = GcidWire.split(value);
        return new GcidId(value, parts.prefix().length());
    }

    static GcidId validated(String value, int prefixLength) {
        return new GcidId(value, prefixLength);
    }

    public String prefix() {
        return value.substring(0, prefixLength);
    }

    public String asString() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof GcidId id && value.equals(id.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }
}
