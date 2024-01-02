package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSA_PS256_PrivateKeySigner extends PrivateKeySigner<KeyPair> {

    public RSA_PS256_PrivateKeySigner(KeyPair privateKey) {

        super(privateKey, JWSAlgorithm.PS256);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        Signature jcaSignature = Signature.getInstance("SHA256withRSAandMGF1");
        jcaSignature.setParameter(pssParameterSpec);

        jcaSignature.initSign(this.getPrivateKey().getPrivate());
        jcaSignature.update(content);

        return jcaSignature.sign();
    }
}
