package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.JWK_to_PublicKey;
import com.danubetech.keyformats.crypto.impl.*;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import inf.um.psmultisign.PSverfKey;
import org.bitcoinj.core.ECKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class PublicKeyVerifierFactory {

    public static PublicKeyVerifier<?> publicKeyVerifierForJWK(JWK jwk, String algorithm) {

        return publicKeyVerifierForKey(
                KeyTypeName_for_JWK.keyTypeName_for_JWK(jwk),
                algorithm,
                JWK_to_PublicKey.JWK_to_anyPublicKey(jwk));
    }

    public static PublicKeyVerifier<?> publicKeyVerifierForKey(KeyTypeName keyTypeName, String algorithm, Object publicKey) {

        if (keyTypeName == null) throw new NullPointerException("No key type name provided.");
        if (algorithm == null) throw new NullPointerException("No algorithm provided.");
        if (publicKey == null) throw new NullPointerException("No public key provided.");

        if (KeyTypeName.RSA.equals(keyTypeName)) {

            if (JWSAlgorithm.RS256.equals(algorithm)) return new RSA_RS256_PublicKeyVerifier((RSAPublicKey) publicKey);
            if (JWSAlgorithm.PS256.equals(algorithm)) return new RSA_PS256_PublicKeyVerifier((RSAPublicKey) publicKey);
        } else if (KeyTypeName.secp256k1.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256K.equals(algorithm)) return new secp256k1_ES256K_PublicKeyVerifier((ECKey) publicKey);
            if (JWSAlgorithm.ES256KCC.equals(algorithm)) return new secp256k1_ES256KCC_PublicKeyVerifier((ECKey) publicKey);
            if (JWSAlgorithm.ES256KRR.equals(algorithm)) return new secp256k1_ES256KRR_PublicKeyVerifier((ECKey) publicKey);
        } else if (KeyTypeName.Bls12381G1.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G1_BBSPlus_PublicKeyVerifier((bbs.signatures.KeyPair) publicKey);
        } else if (KeyTypeName.Bls12381G2.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G2_BBSPlus_PublicKeyVerifier((bbs.signatures.KeyPair) publicKey);
        } else if (KeyTypeName.Bls48581G1.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls48581G1_BBSPlus_PublicKeyVerifier((bbs.signatures.KeyPair) publicKey);
        } else if (KeyTypeName.Bls48581G2.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls48581G2_BBSPlus_PublicKeyVerifier((bbs.signatures.KeyPair) publicKey);
        } else if (KeyTypeName.Ed25519.equals(keyTypeName)) {

            if (JWSAlgorithm.EdDSA.equals(algorithm)) return new Ed25519_EdDSA_PublicKeyVerifier((byte[]) publicKey);
        } else if (KeyTypeName.P_256.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256.equals(algorithm)) return new P_256_ES256_PublicKeyVerifier((ECPublicKey) publicKey);
        } else if (KeyTypeName.P_384.equals(keyTypeName)) {

            if (JWSAlgorithm.ES384.equals(algorithm)) return new P_384_ES384_PublicKeyVerifier((ECPublicKey) publicKey);
        } else if (KeyTypeName.P_521.equals(keyTypeName)) {

            if (JWSAlgorithm.ES512.equals(algorithm)) return new P_521_ES512_PublicKeyVerifier((ECPublicKey) publicKey);
        }else if (KeyTypeName.PsmsBlsSignature2022.equals(keyTypeName)) {

            if (JWSAlgorithm.PSMSAlg.equals(algorithm)) return new PsmsBlsSignature2022_PublicKeyVerifier((PSverfKey) publicKey);
        }else if (KeyTypeName.PsmsBlsSignature2022Proof.equals(keyTypeName)) {

            if (JWSAlgorithm.PSMSAlgProof.equals(algorithm)) return new PsmsBlsSignatureProof2022_PublicKeyVerifier((PSverfKey) publicKey, null);
        }

        throw new IllegalArgumentException("Unsupported public key " + keyTypeName + " and/or algorithm " + algorithm);
    }
}
