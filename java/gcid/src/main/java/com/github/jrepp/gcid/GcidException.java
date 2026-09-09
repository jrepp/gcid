package com.github.jrepp.gcid;

/** Exception raised for malformed or unauthenticated GCID values. */
public final class GcidException extends Exception {
    private static final long serialVersionUID = 1L;

    private final Code code;

    public GcidException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public GcidException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }

    public enum Code {
        INVALID_KEY_LENGTH,
        INVALID_PREFIX,
        INVALID_FORMAT,
        INVALID_BASE58,
        INVALID_PAYLOAD_LENGTH,
        INVALID_SEQUENCE,
        INVALID_LOCATION,
        INVALID_KEY_ID,
        UNEXPECTED_PREFIX,
        UNSUPPORTED_VERSION,
        UNSUPPORTED_SUITE,
        UNSUPPORTED_SCHEMA,
        UNSUPPORTED_KEY_ID,
        UNKNOWN_KEY_ID,
        EMPTY_KEYRING,
        AUTHENTICATION,
        CRYPTO
    }
}
