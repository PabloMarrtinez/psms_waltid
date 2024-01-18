package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.JWK_to_PrivateKey;
import com.danubetech.keyformats.crypto.impl.*;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import inf.um.multisign.MSprivateKey;
import inf.um.multisign.MSverfKey;
import org.bitcoinj.core.ECKey;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

public class PrivateKeySignerFactory {

    public static PrivateKeySigner<?> privateKeySignerForKey(JWK jwk, String algorithm) {

        return privateKeySignerForKey(
                KeyTypeName_for_JWK.keyTypeName_for_JWK(jwk),
                algorithm,
                JWK_to_PrivateKey.JWK_to_anyPrivateKey(jwk));
    }

    public static PrivateKeySigner<?> privateKeySignerForKey(KeyTypeName keyTypeName, String algorithm, Object privateKey) {

        if (keyTypeName == null) throw new NullPointerException("No key type name provided.");
        if (algorithm == null) throw new NullPointerException("No algorithm provided.");
        if (privateKey == null) throw new NullPointerException("No private key provided.");

        if (KeyTypeName.RSA.equals(keyTypeName)) {

            if (JWSAlgorithm.RS256.equals(algorithm)) return new RSA_RS256_PrivateKeySigner((KeyPair) privateKey);
            if (JWSAlgorithm.PS256.equals(algorithm)) return new RSA_PS256_PrivateKeySigner((KeyPair) privateKey);
        } else if (KeyTypeName.secp256k1.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256K.equals(algorithm)) return new secp256k1_ES256K_PrivateKeySigner((ECKey) privateKey);
            if (JWSAlgorithm.ES256KCC.equals(algorithm)) return new secp256k1_ES256KCC_PrivateKeySigner((ECKey) privateKey);
            if (JWSAlgorithm.ES256KRR.equals(algorithm)) return new secp256k1_ES256KRR_PrivateKeySigner((ECKey) privateKey);
        } else if (KeyTypeName.Bls12381G1.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G1_BBSPlus_PrivateKeySigner((bbs.signatures.KeyPair) privateKey);
        } else if (KeyTypeName.Bls12381G2.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G2_BBSPlus_PrivateKeySigner((bbs.signatures.KeyPair) privateKey);
        } else if (KeyTypeName.Bls48581G1.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls48581G1_BBSPlus_PrivateKeySigner((bbs.signatures.KeyPair) privateKey);
        } else if (KeyTypeName.Bls48581G2.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls48581G2_BBSPlus_PrivateKeySigner((bbs.signatures.KeyPair) privateKey);
        } else if (KeyTypeName.Ed25519.equals(keyTypeName)) {

            if (JWSAlgorithm.EdDSA.equals(algorithm)) return new Ed25519_EdDSA_PrivateKeySigner((byte[]) privateKey);
        } else if (KeyTypeName.P_256.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256.equals(algorithm)) return new P_256_ES256_PrivateKeySigner((ECPrivateKey) privateKey);
        } else if (KeyTypeName.P_384.equals(keyTypeName)) {

            if (JWSAlgorithm.ES384.equals(algorithm)) return new P_384_ES384_PrivateKeySigner((ECPrivateKey) privateKey);
        } else if (KeyTypeName.P_521.equals(keyTypeName)) {

            if (JWSAlgorithm.ES512.equals(algorithm)) return new P_521_ES512_PrivateKeySigner((ECPrivateKey) privateKey);
        } else if (KeyTypeName.PsmsBlsSignature2022.equals(keyTypeName)) {

            if (JWSAlgorithm.PSMSAlg.equals(algorithm))
                return new PsmsBlsSignature2022_PrivateKeySigner((MSprivateKey) privateKey);
        }


        throw new IllegalArgumentException("Unsupported private key " + keyTypeName + " and/or algorithm " + algorithm);
    }
}
