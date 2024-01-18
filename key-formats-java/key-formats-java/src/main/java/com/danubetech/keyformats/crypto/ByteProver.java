package com.danubetech.keyformats.crypto;

import inf.um.model.exceptions.MSSetupException;

import java.security.GeneralSecurityException;

public abstract class ByteProver {

    private final String algorithm;

    protected ByteProver(String algorithm) {

        this.algorithm = algorithm;
    }

    public final byte[] sign(byte[] credencial,byte[] presentation ,String algorithm) throws GeneralSecurityException {

        if (! algorithm.equals(this.algorithm)) throw new GeneralSecurityException("Unexpected algorithm " + algorithm + " is different from " + this.algorithm);

        return this.sign(credencial,presentation);
    }

    protected abstract byte[] sign(byte[] credencial ,byte[] presentation) throws GeneralSecurityException;

    public String getAlgorithm() {

        return this.algorithm;
    }
}
