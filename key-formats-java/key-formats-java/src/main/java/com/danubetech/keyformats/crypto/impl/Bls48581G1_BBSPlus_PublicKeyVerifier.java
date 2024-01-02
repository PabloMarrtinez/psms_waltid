package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls48581G1_BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<KeyPair> {

    public Bls48581G1_BBSPlus_PublicKeyVerifier(KeyPair publicKey) {

        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        try {

            return Bbs.blsVerify(this.getPublicKey().publicKey, signature, new byte[][]{signature});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
