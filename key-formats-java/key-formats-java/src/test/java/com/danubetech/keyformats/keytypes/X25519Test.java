package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.*;
import com.danubetech.keyformats.jose.JWK;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class X25519Test {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "OKP",
                      "crv": "X25519",
                      "x": "HDcYn8qmdrOXxBUNDh8wCzFgA_BbSqDzyYZl-Iac_nQ"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "OKP",
                      "crv": "X25519",
                      "x": "HDcYn8qmdrOXxBUNDh8wCzFgA_BbSqDzyYZl-Iac_nQ",
                      "d": "lxnr4guCed8naHgpkHPONJWjTQu3b0J00zyAyPk7Ja8"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Test
	public void testPublicKey() throws Exception {
		byte[] publicKey = JWK_to_PublicKey.JWK_to_X25519PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.X25519PublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 32);

		byte[] publicKey2 = PublicKeyBytes.bytes_to_X25519PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey, publicKey2);
		JWK jwk2 = PublicKey_to_JWK.X25519PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		byte[] privateKey = JWK_to_PrivateKey.JWK_to_X25519PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.X25519PrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 64);

		byte[] privateKey2 = PrivateKeyBytes.bytes_to_X25519PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey, privateKey2);
		JWK jwk2 = PrivateKey_to_JWK.X25519PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
