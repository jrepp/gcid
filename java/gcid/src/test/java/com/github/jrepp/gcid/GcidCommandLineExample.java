package com.github.jrepp.gcid;

import java.nio.charset.StandardCharsets;

public final class GcidCommandLineExample {
    private static final byte[] DEV_KEY =
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes(StandardCharsets.US_ASCII);

    private GcidCommandLineExample() {}

    public static void main(String[] args) throws Exception {
        var prefix = args.length > 0 ? args[0] : "prf";
        var sequence = args.length > 1 ? Long.parseUnsignedLong(args[1]) : 123L;
        var location = args.length > 2 ? Long.parseLong(args[2]) : 42L;

        var codec = GcidCodec.create(DEV_KEY);
        var id = codec.encode(prefix, sequence, location);
        var decoded = codec.decode(prefix, id);

        System.out.println("id=" + id);
        System.out.println("prefix=" + decoded.prefix());
        System.out.println("sequence=" + decoded.unsignedSequenceString());
        System.out.println("location=" + decoded.location().asLong());
        System.out.println("keyId=" + decoded.keyId());
    }
}
