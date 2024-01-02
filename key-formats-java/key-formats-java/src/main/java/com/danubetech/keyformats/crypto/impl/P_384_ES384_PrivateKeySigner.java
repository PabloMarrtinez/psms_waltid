package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.util.ASNUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class P_384_ES384_PrivateKeySigner extends PrivateKeySigner<ECPrivateKey> {

    public P_384_ES384_PrivateKeySigner(ECPrivateKey privateKey) {

        super(privateKey, JWSAlgorithm.ES384);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA384withECDSA");

        jcaSignature.initSign(this.getPrivateKey());
        jcaSignature.update(content);

        try {
            return ASNUtil.asn1ESSignatureToJwsSignature(jcaSignature.sign(), 96);
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
