package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.hyperledger.indy.sdk.IndyException;
import org.hyperledger.indy.sdk.crypto.Crypto;
import org.hyperledger.indy.sdk.wallet.Wallet;

import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;

public class Ed25519_EdDSA_LibIndySigner extends ByteSigner {

    private final Wallet wallet;
    private final String signerVk;

    public Ed25519_EdDSA_LibIndySigner(byte[] privateKey, Wallet wallet, String signerVk) {

        super(JWSAlgorithm.EdDSA);

        this.wallet = wallet;
        this.signerVk = signerVk;
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        try {

            return Crypto.cryptoSign(this.wallet, this.signerVk, content).get();
        } catch (InterruptedException | ExecutionException | IndyException ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
