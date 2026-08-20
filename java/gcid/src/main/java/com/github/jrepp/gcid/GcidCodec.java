package com.github.jrepp.gcid;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.github.jrepp.gcid.GcidException.Code;

/** Encoder and decoder for GCIDv2 using one AES-256-GCM-SIV key ID. */
public final class GcidCodec {
    public static final int VERSION = 0x02;
    public static final int SUITE_AES_256_GCM_SIV = 0x01;
    public static final int SCHEMA_SEQ64_LOC56 = 0x01;
    public static final int DEFAULT_KEY_ID = 0x00;
    public static final int HEADER_LENGTH = 4;
    public static final int LOCATION_LENGTH = 7;
    public static final int SEQUENCE_LENGTH = 8;
    public static final int PLAINTEXT_LENGTH = LOCATION_LENGTH + SEQUENCE_LENGTH;
    public static final int TAG_LENGTH = 16;
    public static final int PAYLOAD_LENGTH = HEADER_LENGTH + PLAINTEXT_LENGTH + TAG_LENGTH;

    private static final byte[] NONCE = new byte[12];
    private static final byte[] AAD_DOMAIN = "GCIDv2".getBytes(StandardCharsets.US_ASCII);
    private static final BigInteger U64_LIMIT = BigInteger.ONE.shiftLeft(64);

    private final int keyId;
    private final byte[] authKey;
    private final SecretKeySpec encKey;
    private final ThreadLocal<Cipher> cipher;

    private GcidCodec(int keyId, byte[] authKey, byte[] encKey) {
        this.keyId = keyId & 0xff;
        this.authKey = authKey;
        this.encKey = new SecretKeySpec(encKey, "AES");
        this.cipher = ThreadLocal.withInitial(() -> {
            try {
                var c = Cipher.getInstance("AES/ECB/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, this.encKey);
                return c;
            } catch (GeneralSecurityException exc) {
                throw new IllegalStateException("failed to initialize AES cipher", exc);
            }
        });
    }

    public static GcidCodec create(byte[] key) throws GcidException {
        return create(key, DEFAULT_KEY_ID);
    }

    public static GcidCodec create(byte[] key, int keyId) throws GcidException {
        if (key.length != 32) {
            throw new GcidException(Code.INVALID_KEY_LENGTH, "key must be exactly 32 bytes, got " + key.length);
        }
        try {
            var keys = deriveKeys(key);
            return new GcidCodec(keyId, keys.authKey(), keys.encKey());
        } catch (GeneralSecurityException exc) {
            throw new GcidException(Code.CRYPTO, "failed to initialize AES", exc);
        }
    }

    public byte[] header() {
        return new byte[] {
                (byte) VERSION,
                (byte) SUITE_AES_256_GCM_SIV,
                (byte) SCHEMA_SEQ64_LOC56,
                (byte) keyId
        };
    }

    public int keyId() {
        return keyId;
    }

    public GcidId encode(String prefix, long sequence) throws GcidException {
        return encode(prefix, sequence, LocationPartition.ZERO);
    }

    public GcidId encode(String prefix, BigInteger sequence) throws GcidException {
        if (sequence.signum() < 0 || sequence.compareTo(U64_LIMIT) >= 0) {
            throw new GcidException(Code.INVALID_SEQUENCE, "sequence must fit in unsigned 64 bits: " + sequence);
        }
        return encode(prefix, sequence.longValue());
    }

    public GcidId encodeWithLocation(String prefix, long sequence, long location) throws GcidException {
        try {
            return encode(prefix, sequence, LocationPartition.fromLong(location));
        } catch (IllegalArgumentException exc) {
            throw new GcidException(Code.INVALID_LOCATION, exc.getMessage(), exc);
        }
    }

    public GcidId encode(String prefix, long sequence, LocationPartition location) throws GcidException {
        GcidWire.validatePrefix(prefix);
        var header = header();
        var plaintext = new byte[PLAINTEXT_LENGTH];
        System.arraycopy(location.rawBytes(), 0, plaintext, 0, LOCATION_LENGTH);
        ByteBuffer.wrap(plaintext, LOCATION_LENGTH, SEQUENCE_LENGTH)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(sequence);

        var encrypted = seal(plaintext, associatedData(prefix, header));
        var payload = new byte[PAYLOAD_LENGTH];
        System.arraycopy(header, 0, payload, 0, HEADER_LENGTH);
        System.arraycopy(encrypted, 0, payload, HEADER_LENGTH, encrypted.length);

        var encoded = GcidWire.base58Encode(payload);
        return GcidId.validated(prefix + "_" + encoded, prefix.length());
    }

    public DecodedGcid decode(String expectedPrefix, GcidId id) throws GcidException {
        return decode(expectedPrefix, id.toString());
    }

    public DecodedGcid decode(String expectedPrefix, String value) throws GcidException {
        GcidWire.validatePrefix(expectedPrefix);
        var parts = GcidWire.decodeParts(value);
        if (!parts.prefix().equals(expectedPrefix)) {
            throw new GcidException(
                    Code.UNEXPECTED_PREFIX,
                    "unexpected prefix: expected " + expectedPrefix + " got " + parts.prefix());
        }
        return decodePayload(parts.prefix(), parts.payload());
    }

    public DecodedGcid decodeAny(GcidId id) throws GcidException {
        return decodeAny(id.toString());
    }

    public DecodedGcid decodeAny(String value) throws GcidException {
        var parts = GcidWire.decodeParts(value);
        return decodePayload(parts.prefix(), parts.payload());
    }

    DecodedGcid decodePayload(String prefix, byte[] payload) throws GcidException {
        if (payload.length != PAYLOAD_LENGTH) {
            throw new GcidException(
                    Code.INVALID_PAYLOAD_LENGTH,
                    "invalid payload length: expected " + PAYLOAD_LENGTH + " got " + payload.length);
        }
        var header = Arrays.copyOfRange(payload, 0, HEADER_LENGTH);
        validateHeader(header);
        var plaintext = open(
                Arrays.copyOfRange(payload, HEADER_LENGTH, payload.length),
                associatedData(prefix, header));
        if (plaintext.length != PLAINTEXT_LENGTH) {
            throw new GcidException(Code.INVALID_PAYLOAD_LENGTH, "invalid plaintext length: " + plaintext.length);
        }
        var location = LocationPartition.fromBytes(Arrays.copyOfRange(plaintext, 0, LOCATION_LENGTH));
        var sequence = ByteBuffer.wrap(plaintext, LOCATION_LENGTH, SEQUENCE_LENGTH)
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
        return new DecodedGcid(prefix, sequence, location, header, header[3] & 0xff);
    }

    private void validateHeader(byte[] header) throws GcidException {
        if ((header[0] & 0xff) != VERSION) {
            throw new GcidException(Code.UNSUPPORTED_VERSION, "unsupported GCID version: " + (header[0] & 0xff));
        }
        if ((header[1] & 0xff) != SUITE_AES_256_GCM_SIV) {
            throw new GcidException(Code.UNSUPPORTED_SUITE, "unsupported crypto suite: " + (header[1] & 0xff));
        }
        if ((header[2] & 0xff) != SCHEMA_SEQ64_LOC56) {
            throw new GcidException(Code.UNSUPPORTED_SCHEMA, "unsupported payload schema: " + (header[2] & 0xff));
        }
        if ((header[3] & 0xff) != keyId) {
            throw new GcidException(
                    Code.UNSUPPORTED_KEY_ID,
                    "unsupported key id: expected " + keyId + " got " + (header[3] & 0xff));
        }
    }

    private byte[] seal(byte[] plaintext, byte[] aad) throws GcidException {
        var tag = tag(plaintext, aad);
        var ciphertext = aesCtr(tag, plaintext);
        var out = Arrays.copyOf(ciphertext, ciphertext.length + TAG_LENGTH);
        System.arraycopy(tag, 0, out, ciphertext.length, TAG_LENGTH);
        return out;
    }

    private byte[] open(byte[] ciphertextAndTag, byte[] aad) throws GcidException {
        if (ciphertextAndTag.length < TAG_LENGTH) {
            throw new GcidException(Code.AUTHENTICATION, "authentication failed");
        }
        var tagOffset = ciphertextAndTag.length - TAG_LENGTH;
        var tag = Arrays.copyOfRange(ciphertextAndTag, tagOffset, ciphertextAndTag.length);
        var plaintext = aesCtr(tag, Arrays.copyOfRange(ciphertextAndTag, 0, tagOffset));
        var expected = tag(plaintext, aad);
        if (!constantTimeEquals(tag, expected)) {
            throw new GcidException(Code.AUTHENTICATION, "authentication failed");
        }
        return plaintext;
    }

    private byte[] tag(byte[] plaintext, byte[] aad) throws GcidException {
        try {
            var s = Polyval.hash(authKey, aad, plaintext);
            for (int i = 0; i < NONCE.length; i++) {
                s[i] ^= NONCE[i];
            }
            s[15] &= 0x7f;
            return encryptBlock(s);
        } catch (GeneralSecurityException | IllegalStateException exc) {
            throw new GcidException(Code.CRYPTO, "failed to compute authentication tag", exc);
        }
    }

    private byte[] aesCtr(byte[] tag, byte[] input) throws GcidException {
        try {
            var counter = tag.clone();
            counter[15] |= (byte) 0x80;
            var output = new byte[input.length];
            var stream = new byte[16];
            for (int offset = 0; offset < input.length;) {
                stream = encryptBlock(counter);
                var n = Math.min(stream.length, input.length - offset);
                for (int i = 0; i < n; i++) {
                    output[offset + i] = (byte) (input[offset + i] ^ stream[i]);
                }
                offset += n;
                incrementCounter(counter);
            }
            return output;
        } catch (GeneralSecurityException | IllegalStateException exc) {
            throw new GcidException(Code.CRYPTO, "failed AES-CTR operation", exc);
        }
    }

    private byte[] encryptBlock(byte[] block) throws GeneralSecurityException {
        return cipher.get().doFinal(block);
    }

    private static byte[] associatedData(String prefix, byte[] header) {
        var prefixBytes = prefix.getBytes(StandardCharsets.US_ASCII);
        var aad = new byte[AAD_DOMAIN.length + 1 + prefixBytes.length + 1 + HEADER_LENGTH];
        var offset = 0;
        System.arraycopy(AAD_DOMAIN, 0, aad, offset, AAD_DOMAIN.length);
        offset += AAD_DOMAIN.length + 1;
        System.arraycopy(prefixBytes, 0, aad, offset, prefixBytes.length);
        offset += prefixBytes.length + 1;
        System.arraycopy(header, 0, aad, offset, HEADER_LENGTH);
        return aad;
    }

    private static DerivedKeys deriveKeys(byte[] key) throws GeneralSecurityException {
        var keySpec = new SecretKeySpec(key, "AES");
        var authKey = new byte[16];
        var encKey = new byte[32];
        var input = new byte[16];
        System.arraycopy(NONCE, 0, input, 4, NONCE.length);
        for (int counter = 0; counter < 6; counter++) {
            ByteBuffer.wrap(input, 0, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(counter);
            var encrypted = aesBlock(keySpec, input);
            if (counter < 2) {
                System.arraycopy(encrypted, 0, authKey, counter * 8, 8);
            } else {
                System.arraycopy(encrypted, 0, encKey, (counter - 2) * 8, 8);
            }
        }
        return new DerivedKeys(authKey, encKey);
    }

    private static byte[] aesBlock(SecretKeySpec key, byte[] block) throws GeneralSecurityException {
        var cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(block);
    }

    private static void incrementCounter(byte[] counter) {
        var value = ByteBuffer.wrap(counter, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        ByteBuffer.wrap(counter, 0, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(value + 1);
    }

    private static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        var diff = 0;
        for (int i = 0; i < left.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    private record DerivedKeys(byte[] authKey, byte[] encKey) {}
}
