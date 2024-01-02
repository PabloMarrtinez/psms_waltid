package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls12381G1_BBSPlus_PrivateKeySigner extends PrivateKeySigner<KeyPair> {

    public Bls12381G1_BBSPlus_PrivateKeySigner(KeyPair privateKey) {

        super(privateKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        try {

            return Bbs.blsSign(this.getPrivateKey().secretKey, this.getPrivateKey().publicKey, new byte[][]{content});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
