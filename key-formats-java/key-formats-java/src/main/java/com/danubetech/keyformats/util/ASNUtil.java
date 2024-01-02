package com.danubetech.keyformats.util;

import java.io.IOException;

public class ASNUtil {

    public static byte[] asn1ESSignatureToJwsSignature(final byte[] asn1ESSignature, final int outputLength) throws IOException {

        // Adapted from org.apache.xml.security.algorithms.implementations.SignatureECDSA

        if (asn1ESSignature.length < 8 || asn1ESSignature[0] != 48) throw new IOException("Invalid format of ECDSA signature");

        int offset;
        if (asn1ESSignature[1] > 0)
            offset = 2;
        else if (asn1ESSignature[1] == (byte) 0x81)
            offset = 3;
        else
            throw new IOException("Invalid format of ECDSA signature");

        byte rLength = asn1ESSignature[offset + 1];

        int i = rLength;
        while ((i > 0) && (asn1ESSignature[(offset + 2 + rLength) - i] == 0)) i--;

        byte sLength = asn1ESSignature[offset + 2 + rLength + 1];

        int j = sLength;
        while ((j > 0) && (asn1ESSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0)) j--;

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength/2);

        if ((asn1ESSignature[offset - 1] & 0xff) != asn1ESSignature.length - offset
                || (asn1ESSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || asn1ESSignature[offset] != 2
                || asn1ESSignature[offset + 2 + rLength] != 2) {
            throw new IOException("Invalid format of ECDSA signature");
        }

        byte[] jwsSignature = new byte[2*rawLen];

        System.arraycopy(asn1ESSignature, (offset + 2 + rLength) - i, jwsSignature, rawLen - i, i);
        System.arraycopy(asn1ESSignature, (offset + 2 + rLength + 2 + sLength) - j, jwsSignature, 2*rawLen - j, j);

        return jwsSignature;
    }

    public static byte[] jwsSignatureToAsn1ESSignature(final byte[] jwsSignature) throws IOException {

        // Adapted from org.apache.xml.security.algorithms.implementations.SignatureECDSA

        int rawLen = jwsSignature.length / 2;

        int i = rawLen;
        while ((i > 0) && (jwsSignature[rawLen - i] == 0)) i--;

        int j = i;
        if (jwsSignature[rawLen - i] < 0) j += 1;

        int k = rawLen;
        while ((k > 0) && (jwsSignature[2 * rawLen - k] == 0)) k--;

        int l = k;
        if (jwsSignature[2 * rawLen - k] < 0) l += 1;

        int len = 2 + j + 2 + l;

        if (len > 255) throw new IllegalArgumentException("Invalid ECDSA signature format");

        int offset;

        final byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }
}
