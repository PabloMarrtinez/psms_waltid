package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.*;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class P_384Test extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "K3-TGpdCapZuw3G9anqdhHakApxVwQ8CACFUSQ4yvV1ZQw5MeLsknANXQ6w95_m2",
                      "y": "cT0oZj26FpjLYTUsb1NJ85pj8GBU6v3SkHRLl_zLFuoHGcDGgzDNyxdgzdNNfRZD"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "K3-TGpdCapZuw3G9anqdhHakApxVwQ8CACFUSQ4yvV1ZQw5MeLsknANXQ6w95_m2",
                      "y": "cT0oZj26FpjLYTUsb1NJ85pj8GBU6v3SkHRLl_zLFuoHGcDGgzDNyxdgzdNNfRZD",
                      "d": "g-NvpP9jH-w_mrfl3TOq8mrwNJ4Cn9z4H61MpAYVG8h8Dh9KpQ5GRPVnArvi0i5Z"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.P_384;
	}

	@Override
	List<String> getAlgorithms() {
		return Collections.singletonList(JWSAlgorithm.ES384);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_P_384PrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_P_384PublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		ECPublicKey publicKey = JWK_to_PublicKey.JWK_to_P_384PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.P_384PublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 97);

		ECPublicKey publicKey2 = PublicKeyBytes.bytes_to_P_384PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey.getEncoded(), publicKey2.getEncoded());
		JWK jwk2 = PublicKey_to_JWK.P_384PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		ECPrivateKey privateKey = JWK_to_PrivateKey.JWK_to_P_384PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.P_384PrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 48);

		ECPrivateKey privateKey2 = PrivateKeyBytes.bytes_to_P_384PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey.getEncoded(), privateKey2.getEncoded());
		JWK jwk2 = PrivateKey_to_JWK.P_384PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
