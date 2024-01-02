package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static org.bitcoinj.core.ECKey.CURVE;

public class secp256k1_ES256KCC_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256KCC_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256KCC);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        byte[] r = new byte[32];
        byte[] s = new byte[32];
        byte[] v = new byte[1];
        System.arraycopy(signature, 0, r, 0, r.length);
        System.arraycopy(signature, 32, s, 0, s.length);
        System.arraycopy(signature, 64, v, 0, v.length);

        ECDSASigner signer = new ECDSASigner();

        ECKey ec = ECKey.fromPublicOnly(this.getPublicKey());

        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(ec.getPubKeyPoint(), CURVE);
        signer.init(false, publicKey);

        Sign.SignatureData sig = new Sign.SignatureData(v, r, s);
        Sign.signedMessageToKey(content, sig);

        byte[] hash = Hash.sha3(content);

        return signer.verifySignature(hash, new BigInteger(1, r), new BigInteger(1, s));
    }
}
