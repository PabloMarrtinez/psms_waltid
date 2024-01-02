package com.danubetech.keyformats.util;

import java.math.BigInteger;
import java.util.Arrays;

public class ByteArrayUtil {

    public static byte[] bigIntegertoByteArray(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();
        int bitLength = bytes.length * 8;
        if (bigInteger.bitLength() == (bitLength-8)) {
            byte[] newBytes = new byte[bytes.length-1];
            System.arraycopy(bytes, 1, newBytes, 0, newBytes.length);
            bytes = newBytes;
        }
        return bytes;
    }

    public static byte[] padArrayZeros(byte[] bytes, int length) {
        if (bytes.length >= length) return bytes;
        byte[] newBytes = new byte[length];
        Arrays.fill(newBytes, 0, length-bytes.length, (byte) 0);
        System.arraycopy(bytes, 0, newBytes, length-bytes.length, bytes.length);
        return newBytes;
    }
}
