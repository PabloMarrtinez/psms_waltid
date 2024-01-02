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

public class P_256Test extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "NNKq5JQTh51m4oGRKLZkXw43n8-c2pwptOrrbUSwgtY",
                      "y": "wDHqdnu8ydJv_zFqLpybhaRH9j62ShPFRrHYpUhWuu8"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "NNKq5JQTh51m4oGRKLZkXw43n8-c2pwptOrrbUSwgtY",
                      "y": "wDHqdnu8ydJv_zFqLpybhaRH9j62ShPFRrHYpUhWuu8",
                      "d": "duGXAvbPzfAcoeLqlXjfkfV3DqsOds5qi-uwjV1nD-A"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.P_256;
	}

	@Override
	List<String> getAlgorithms() {
		return Collections.singletonList(JWSAlgorithm.ES256);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_P_256PrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_P_256PublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		ECPublicKey publicKey = JWK_to_PublicKey.JWK_to_P_256PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.P_256PublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 65);

		ECPublicKey publicKey2 = PublicKeyBytes.bytes_to_P_256PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey.getEncoded(), publicKey2.getEncoded());
		JWK jwk2 = PublicKey_to_JWK.P_256PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		ECPrivateKey privateKey = JWK_to_PrivateKey.JWK_to_P_256PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.P_256PrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 32);

		ECPrivateKey privateKey2 = PrivateKeyBytes.bytes_to_P_256PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey.getEncoded(), privateKey2.getEncoded());
		JWK jwk2 = PrivateKey_to_JWK.P_256PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
