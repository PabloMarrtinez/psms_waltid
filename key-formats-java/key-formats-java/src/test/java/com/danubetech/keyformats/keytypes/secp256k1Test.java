package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.*;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.bitcoinj.core.ECKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class secp256k1Test extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "secp256k1",
                      "x": "L_SbJlSbQ4KmFRL-X1B9UvaYr4ADKT9BB4qfkH5JC0g",
                      "y": "RqENlFt0h1p6ezVjecuAPjs9A3XYtqQ_4tHS15bYnQs"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "secp256k1",
                      "x": "L_SbJlSbQ4KmFRL-X1B9UvaYr4ADKT9BB4qfkH5JC0g",
                      "y": "RqENlFt0h1p6ezVjecuAPjs9A3XYtqQ_4tHS15bYnQs",
                      "d": "I7FRcpukxhOfpvH28R97rOZ78L8Os2Q-c1LjuHte8Tc"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.secp256k1;
	}

	@Override
	List<String> getAlgorithms() {
		return Arrays.asList(JWSAlgorithm.ES256K, JWSAlgorithm.ES256KCC, JWSAlgorithm.ES256KRR);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_secp256k1PrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_secp256k1PublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		ECKey publicKey = JWK_to_PublicKey.JWK_to_secp256k1PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.secp256k1PublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 65);

		ECKey publicKey2 = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey.getPubKey(), publicKey2.getPubKey());
		JWK jwk2 = PublicKey_to_JWK.secp256k1PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		ECKey privateKey = JWK_to_PrivateKey.JWK_to_secp256k1PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.secp256k1PrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 32);

		ECKey privateKey2 = PrivateKeyBytes.bytes_to_secp256k1PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey.getPrivKeyBytes(), privateKey2.getPrivKeyBytes());
		JWK jwk2 = PrivateKey_to_JWK.secp256k1PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
