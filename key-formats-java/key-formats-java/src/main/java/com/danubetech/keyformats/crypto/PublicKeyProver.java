package com.danubetech.keyformats.crypto;

public abstract class PublicKeyProver <T> extends ByteProver {

    private final T privateKey;

    protected PublicKeyProver(T privateKey, String algorithm) {

        super(algorithm);

        this.privateKey = privateKey;
    }

    protected T getPrivateKey() {

        return this.privateKey;
    }
}
