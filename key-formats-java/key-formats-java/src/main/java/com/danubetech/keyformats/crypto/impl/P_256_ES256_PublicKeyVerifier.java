package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.util.ASNUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

public class P_256_ES256_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public P_256_ES256_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA256withECDSA");

        jcaSignature.initVerify(this.getPublicKey());
        jcaSignature.update(content);

        try {
            return jcaSignature.verify(ASNUtil.jwsSignatureToAsn1ESSignature(signature));
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
