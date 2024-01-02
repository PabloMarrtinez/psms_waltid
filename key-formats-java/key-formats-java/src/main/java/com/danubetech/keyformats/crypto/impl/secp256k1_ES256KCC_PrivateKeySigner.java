package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

public class secp256k1_ES256KCC_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256KCC_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256KCC);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        byte[] hash = Hash.sha3(content);

        ECKeyPair ec = ECKeyPair.create(this.getPrivateKey().getPrivKey());
        ECDSASignature ecdsaSignature = ec.sign(hash);

        int recId = -1;

        int headerByte;
        for(headerByte = 0; headerByte < 4; ++headerByte) {
            BigInteger k = Sign.recoverFromSignature(headerByte, ecdsaSignature, hash);
            if (k != null && k.equals(ec.getPublicKey())) {
                recId = headerByte;
                break;
            }
        }

        if (recId == -1) {
            throw new RuntimeException("Could not construct a recoverable key. Are your credentials valid?");
        } else {
            headerByte = recId + 27;
            byte[] v = new byte[]{(byte)headerByte};
            byte[] r = Numeric.toBytesPadded(ecdsaSignature.r, 32);
            byte[] s = Numeric.toBytesPadded(ecdsaSignature.s, 32);
            byte[] signatureBytes = new byte[65];
            System.arraycopy(r, 0, signatureBytes, 0, r.length);
            System.arraycopy(s, 0, signatureBytes, 32, s.length);
            System.arraycopy(v, 0, signatureBytes, 64, v.length);
            return signatureBytes;
        }
    }
}
