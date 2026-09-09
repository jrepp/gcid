package com.github.jrepp.gcid;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

final class Polyval {
    private Polyval() {}

    static byte[] hash(byte[] h, byte[] aad, byte[] plaintext) {
        var hPrime = mulXGhash(reverse(h));
        var state = new byte[16];
        update(state, hPrime, aad);
        update(state, hPrime, plaintext);
        var lengthBlock = new byte[16];
        ByteBuffer.wrap(lengthBlock, 0, 8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong((long) aad.length * 8);
        ByteBuffer.wrap(lengthBlock, 8, 8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong((long) plaintext.length * 8);
        updateBlock(state, hPrime, lengthBlock);
        return reverse(state);
    }

    static byte[] hashBlocks(byte[] h, byte[] input) {
        var hPrime = mulXGhash(reverse(h));
        var state = new byte[16];
        update(state, hPrime, input);
        return reverse(state);
    }

    private static void update(byte[] state, byte[] h, byte[] data) {
        var offset = 0;
        while (offset < data.length) {
            var block = new byte[16];
            var n = Math.min(16, data.length - offset);
            System.arraycopy(data, offset, block, 0, n);
            updateBlock(state, h, block);
            offset += n;
        }
    }

    private static void updateBlock(byte[] state, byte[] h, byte[] block) {
        var reversed = reverse(block);
        for (int i = 0; i < 16; i++) {
            state[i] ^= reversed[i];
        }
        var product = ghashMul(state, h);
        System.arraycopy(product, 0, state, 0, 16);
    }

    private static byte[] reverse(byte[] input) {
        var out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = input[15 - i];
        }
        return out;
    }

    private static byte[] mulXGhash(byte[] input) {
        var out = shiftRight(input);
        if ((input[15] & 1) != 0) {
            out[0] ^= (byte) 0xe1;
        }
        return out;
    }

    private static byte[] ghashMul(byte[] x, byte[] y) {
        var z = new byte[16];
        var v = y.clone();
        for (int i = 0; i < 128; i++) {
            if (bit(x, i) != 0) {
                xor(z, v);
            }
            var lsb = v[15] & 1;
            v = shiftRight(v);
            if (lsb != 0) {
                v[0] ^= (byte) 0xe1;
            }
        }
        return z;
    }

    private static int bit(byte[] block, int i) {
        return (block[i / 8] >>> (7 - (i % 8))) & 1;
    }

    private static byte[] shiftRight(byte[] input) {
        var out = new byte[16];
        var carry = 0;
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) (((input[i] & 0xff) >>> 1) | carry);
            carry = (input[i] & 1) << 7;
        }
        return out;
    }

    private static void xor(byte[] dst, byte[] src) {
        for (int i = 0; i < dst.length; i++) {
            dst[i] ^= src[i];
        }
    }

    static byte[] hex(String value) {
        var out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static String hex(byte[] bytes) {
        var out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format("%02x", b & 0xff));
        }
        return out.toString();
    }

    static boolean equalsHex(byte[] bytes, String hex) {
        return Arrays.equals(bytes, hex(hex));
    }
}
