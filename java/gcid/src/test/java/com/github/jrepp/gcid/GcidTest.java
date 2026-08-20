package com.github.jrepp.gcid;

import java.math.BigInteger;
import java.util.Arrays;
import com.github.jrepp.gcid.GcidException.Code;

public final class GcidTest {
    private static final byte[] DEV_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes();
    private static final byte[] ALT_KEY = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY".getBytes();

    public static void main(String[] args) throws Exception {
        specVectors();
        decodeAnyAndTypedId();
        relabelingFailsAuthentication();
        wrongExpectedPrefixFailsBeforeAuthentication();
        rejectsInvalidInputs();
        tamperingFails();
        keyring();
        polyvalRfcExample();
        System.out.println("Java GCID tests passed");
    }

    private static void specVectors() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        var vectors = new Vector[] {
                new Vector("prf", 0, 123, "619d1d6dc26f2d50845c51ee5b6f37",
                        "f8015069da306ae7ee323ddcb428c45f",
                        "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ"),
                new Vector("asset", 0, 456, "be57802f7f0f0123077557a54ea928",
                        "49ee9bd1fd58fd7476aef836e2d54ff8",
                        "asset_Cbds3PQ1ZC2vzDFLB7qWod4hHnAuFwt4uqFH6NbKL1ZBCvT"),
                new Vector("asset", 42, 123, "1c313f1a04c3c016de1298477fe0b8",
                        "1f05d8b70283707ad41305890d03d7fe",
                        "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"),
                new Vector("prf", 0, 0, "f3e6a0e5334c0076886a9dc80a9d4a",
                        "b5fb28e63cede5a351e1e72f70b4f0fe",
                        "prf_Cbds4CmMHP4273kXPwFQ8DQCPu3sd4CSAmhYDA7RzkTEGmb"),
                new Vector("prf", 0, -1L, "0a4401ea838160882402e258cc8de4",
                        "3f8c3ad5f654505d698dde38a96175e5",
                        "prf_Cbdrze8v48sf8q2jPwrCf3TMB4Gs3YiHcnki91GDYsBwmxp")
        };
        for (var vector : vectors) {
            var id = codec.encodeWithLocation(vector.prefix, vector.sequence, vector.location);
            assertEquals(vector.id, id.toString(), "encoded vector");
            var decoded = codec.decode(vector.prefix, id);
            assertEquals(vector.sequence, decoded.sequence(), "decoded sequence");
            assertEquals(vector.location, decoded.location().asLong(), "decoded location");
            var payload = GcidWire.decodeParts(id.toString()).payload();
            assertEquals(vector.ciphertext,
                    Polyval.hex(Arrays.copyOfRange(payload, GcidCodec.HEADER_LENGTH,
                            GcidCodec.HEADER_LENGTH + GcidCodec.PLAINTEXT_LENGTH)),
                    "ciphertext");
            assertEquals(vector.tag,
                    Polyval.hex(Arrays.copyOfRange(payload,
                            GcidCodec.HEADER_LENGTH + GcidCodec.PLAINTEXT_LENGTH,
                            payload.length)),
                    "tag");
        }
        var max = codec.encode("prf", new BigInteger("18446744073709551615"));
        assertEquals(vectors[4].id, max.toString(), "BigInteger max u64 encode");
    }

    private static void decodeAnyAndTypedId() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        var id = codec.encode("asset", 456);
        var parsed = GcidId.parse(id.toString());
        assertEquals("asset", parsed.prefix(), "typed prefix");
        assertEquals(id.toString(), parsed.asString(), "typed string");
        var decoded = codec.decodeAny(parsed);
        assertEquals("asset", decoded.prefix(), "decoded any prefix");
        assertEquals(456L, decoded.sequence(), "decoded any sequence");
    }

    private static void relabelingFailsAuthentication() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        var id = codec.encode("prf", 123).toString();
        expectFailure(() -> codec.decode("asset", "asset_" + id.substring("prf_".length())),
                Code.AUTHENTICATION);
    }

    private static void wrongExpectedPrefixFailsBeforeAuthentication() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        var id = codec.encode("prf", 123);
        expectFailure(() -> codec.decode("asset", id), Code.UNEXPECTED_PREFIX);
    }

    private static void rejectsInvalidInputs() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        for (var prefix : new String[] {"", "bad_prefix", "bad prefix", "café"}) {
            expectFailure(() -> codec.encode(prefix, 1), Code.INVALID_PREFIX);
        }
        expectFailure(() -> codec.encodeWithLocation("asset", 1, 1L << 56), Code.INVALID_LOCATION);
        expectFailure(() -> GcidCodec.create(Arrays.copyOf(DEV_KEY, 31)), Code.INVALID_KEY_LENGTH);
        expectFailure(() -> GcidId.parse("prf_payload_extra"), Code.INVALID_FORMAT);
        expectFailure(() -> GcidId.parse("prf_"), Code.INVALID_FORMAT);
        expectFailure(() -> codec.decodeAny("prf_0"), Code.INVALID_BASE58);
        expectFailure(() -> codec.decodeAny("prf_1"), Code.INVALID_PAYLOAD_LENGTH);
        expectFailure(() -> codec.encode("prf", BigInteger.ONE.negate()), Code.INVALID_SEQUENCE);
    }

    private static void tamperingFails() throws Exception {
        var codec = GcidCodec.create(DEV_KEY);
        var id = codec.encode("prf", 123).toString();
        expectFailure(() -> codec.decode("prf", mutate(id, 0, 3, false)), Code.UNSUPPORTED_VERSION);
        expectFailure(() -> codec.decode("prf", mutate(id, 1, 2, false)), Code.UNSUPPORTED_SUITE);
        expectFailure(() -> codec.decode("prf", mutate(id, 2, 2, false)), Code.UNSUPPORTED_SCHEMA);
        expectFailure(() -> codec.decode("prf", mutate(id, 3, 1, false)), Code.UNSUPPORTED_KEY_ID);
        expectFailure(() -> codec.decode("prf", mutate(id, 4, 1, true)), Code.AUTHENTICATION);
        expectFailure(() -> codec.decode("prf", mutate(id, GcidCodec.PAYLOAD_LENGTH - 1, 1, true)),
                Code.AUTHENTICATION);
    }

    private static void keyring() throws Exception {
        var codec = GcidCodec.create(DEV_KEY, 7);
        assertEquals(7, codec.keyId(), "codec key id");
        var id = codec.encode("prf", 99);
        var ring = new GcidKeyring().addKey(1, ALT_KEY).addKey(7, DEV_KEY);
        var decoded = ring.decodeAny(id);
        assertEquals(7, decoded.keyId(), "keyring key id");
        assertEquals(99L, decoded.sequence(), "keyring sequence");
        assertEquals(99L, ring.decode("prf", id).sequence(), "keyring decode");
        expectFailure(() -> new GcidKeyring().addKey(1, Arrays.copyOf(DEV_KEY, 31)), Code.INVALID_KEY_LENGTH);
        expectFailure(() -> new GcidKeyring().encode("prf", 1), Code.EMPTY_KEYRING);
        expectFailure(() -> new GcidKeyring().addKey(1, ALT_KEY).decodeAny(id.toString()), Code.UNKNOWN_KEY_ID);
    }

    private static void polyvalRfcExample() {
        var h = Polyval.hex("25629347589242761d31f826ba4b757b");
        var input = Polyval.hex(
                "4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362");
        var got = Polyval.hashBlocks(h, input);
        assertTrue(Polyval.equalsHex(got, "f7a3b47b846119fae5b7866cf5e5b77e"), "POLYVAL RFC example");
    }

    private static String mutate(String id, int offset, int value, boolean xor) throws Exception {
        var parts = GcidWire.decodeParts(id);
        var payload = parts.payload();
        if (xor) {
            payload[offset] ^= (byte) value;
        } else {
            payload[offset] = (byte) value;
        }
        return parts.prefix() + "_" + GcidWire.base58Encode(payload);
    }

    private static void expectFailure(ThrowingRunnable runnable, Code code) throws Exception {
        try {
            runnable.run();
        } catch (GcidException exc) {
            if (exc.code() != code) {
                throw new AssertionError("expected code " + code + ", got " + exc.code() + ": " + exc);
            }
            return;
        }
        throw new AssertionError("expected failure with code " + code);
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + " got " + actual);
        }
    }

    private static void assertEquals(long expected, long actual, String label) {
        if (expected != actual) {
            throw new AssertionError(label + ": expected " + expected + " got " + actual);
        }
    }

    private static void assertTrue(boolean value, String label) {
        if (!value) {
            throw new AssertionError(label);
        }
    }

    private record Vector(String prefix, long location, long sequence, String ciphertext, String tag, String id) {}

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
