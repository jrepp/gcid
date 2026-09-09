package com.github.jrepp.gcid;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import com.github.jrepp.gcid.GcidException.Code;

final class GcidWire {
    private static final String BASE58_ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int[] BASE58_INDEX = new int[256];
    private static final BigInteger BIG_58 = BigInteger.valueOf(58);

    static {
        Arrays.fill(BASE58_INDEX, -1);
        for (int i = 0; i < BASE58_ALPHABET.length(); i++) {
            BASE58_INDEX[BASE58_ALPHABET.charAt(i)] = i;
        }
    }

    private GcidWire() {}

    static Parts split(String value) throws GcidException {
        var separator = value.indexOf('_');
        if (separator < 0 || value.indexOf('_', separator + 1) >= 0) {
            throw new GcidException(Code.INVALID_FORMAT, "invalid GCID format");
        }
        var prefix = value.substring(0, separator);
        var payload = value.substring(separator + 1);
        validatePrefix(prefix);
        if (payload.isEmpty()) {
            throw new GcidException(Code.INVALID_FORMAT, "invalid GCID format");
        }
        return new Parts(prefix, payload, null);
    }

    static Parts decodeParts(String value) throws GcidException {
        var parts = split(value);
        return new Parts(parts.prefix(), parts.encodedPayload(), base58Decode(parts.encodedPayload()));
    }

    static void validatePrefix(String prefix) throws GcidException {
        if (prefix.isEmpty()) {
            throw new GcidException(Code.INVALID_PREFIX, "prefix must be non-empty visible ASCII without underscore");
        }
        var bytes = prefix.getBytes(StandardCharsets.UTF_8);
        if (bytes.length != prefix.length()) {
            throw new GcidException(Code.INVALID_PREFIX, "prefix must be ASCII: " + prefix);
        }
        for (int i = 0; i < prefix.length(); i++) {
            var c = prefix.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '_') {
                throw new GcidException(
                        Code.INVALID_PREFIX,
                        "prefix must be non-empty visible ASCII without underscore: " + prefix);
            }
        }
    }

    static String base58Encode(byte[] input) {
        var zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        var value = new BigInteger(1, input);
        var encoded = new StringBuilder();
        while (value.signum() > 0) {
            var divRem = value.divideAndRemainder(BIG_58);
            value = divRem[0];
            encoded.append(BASE58_ALPHABET.charAt(divRem[1].intValue()));
        }
        for (int i = 0; i < zeros; i++) {
            encoded.append(BASE58_ALPHABET.charAt(0));
        }
        return encoded.reverse().toString();
    }

    static byte[] base58Decode(String input) throws GcidException {
        var value = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            var c = input.charAt(i);
            if (c > 255 || BASE58_INDEX[c] < 0) {
                throw new GcidException(Code.INVALID_BASE58, "invalid base58 payload");
            }
            value = value.multiply(BIG_58).add(BigInteger.valueOf(BASE58_INDEX[c]));
        }
        var decoded = value.toByteArray();
        if (decoded.length > 1 && decoded[0] == 0) {
            decoded = Arrays.copyOfRange(decoded, 1, decoded.length);
        }
        var zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == BASE58_ALPHABET.charAt(0)) {
            zeros++;
        }
        if (zeros == 0) {
            return decoded;
        }
        var out = new byte[zeros + decoded.length];
        System.arraycopy(decoded, 0, out, zeros, decoded.length);
        return out;
    }

    record Parts(String prefix, String encodedPayload, byte[] payload) {}
}
