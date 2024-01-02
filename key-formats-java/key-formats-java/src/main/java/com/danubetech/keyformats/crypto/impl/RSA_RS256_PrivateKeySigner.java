package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;

public class RSA_RS256_PrivateKeySigner extends PrivateKeySigner<KeyPair> {

    public RSA_RS256_PrivateKeySigner(KeyPair privateKey) {

        super(privateKey, JWSAlgorithm.RS256);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA256withRSA");

        jcaSignature.initSign(this.getPrivateKey().getPrivate());
        jcaSignature.update(content);

        return jcaSignature.sign();
    }
}
