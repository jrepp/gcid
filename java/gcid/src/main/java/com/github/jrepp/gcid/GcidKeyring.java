package com.github.jrepp.gcid;

import com.github.jrepp.gcid.GcidException.Code;

/** Multi-key GCIDv2 decoder with one default encoder key. */
public final class GcidKeyring {
    private final GcidCodec[] codecs = new GcidCodec[256];
    private int defaultKeyId;
    private boolean hasDefault;

    public GcidKeyring addKey(int keyId, byte[] key) throws GcidException {
        var normalized = keyId & 0xff;
        codecs[normalized] = GcidCodec.create(key, normalized);
        if (!hasDefault) {
            defaultKeyId = normalized;
            hasDefault = true;
        }
        return this;
    }

    public GcidId encode(String prefix, long sequence) throws GcidException {
        return defaultCodec().encode(prefix, sequence);
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

    public DecodedGcid decode(String expectedPrefix, GcidId id) throws GcidException {
        return decode(expectedPrefix, id.toString());
    }

    public DecodedGcid decodeAny(GcidId id) throws GcidException {
        return decodeAny(id.toString());
    }

    public DecodedGcid decodeAny(String value) throws GcidException {
        var parts = GcidWire.decodeParts(value);
        return decodePayload(parts.prefix(), parts.payload());
    }

    private DecodedGcid decodePayload(String prefix, byte[] payload) throws GcidException {
        if (payload.length < GcidCodec.HEADER_LENGTH) {
            throw new GcidException(
                    Code.INVALID_PAYLOAD_LENGTH,
                    "invalid payload length: expected " + GcidCodec.PAYLOAD_LENGTH + " got " + payload.length);
        }
        var keyId = payload[3] & 0xff;
        var codec = codecs[keyId];
        if (codec == null) {
            throw new GcidException(Code.UNKNOWN_KEY_ID, "unknown key id: " + keyId);
        }
        return codec.decodePayload(prefix, payload);
    }

    private GcidCodec defaultCodec() throws GcidException {
        if (!hasDefault || codecs[defaultKeyId] == null) {
            throw new GcidException(Code.EMPTY_KEYRING, "keyring is empty");
        }
        return codecs[defaultKeyId];
    }
}
