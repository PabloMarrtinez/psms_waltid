package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.util.ASNUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class P_256_ES256_PrivateKeySigner extends PrivateKeySigner<ECPrivateKey> {

    public P_256_ES256_PrivateKeySigner(ECPrivateKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA256withECDSA");

        jcaSignature.initSign(this.getPrivateKey());
        jcaSignature.update(content);

        try {
            return ASNUtil.asn1ESSignatureToJwsSignature(jcaSignature.sign(), 64);
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
