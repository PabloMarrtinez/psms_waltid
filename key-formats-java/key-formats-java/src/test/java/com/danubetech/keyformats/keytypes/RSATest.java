package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.*;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSATest extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "RSA",
                      "e": "AQAB",
                      "n": "lqF6-rWlBHPB7fEGQ46iKBFplLY5qJaWX1kH0bcUmQMgjsVWlOpNb6I9NTeuSf3JM54vDS_8iZvmJ7bsQOWBCZEv_rWW4kMJSjcoAdhDt_5sU3g2mFbv7KLRpsfWSN8G4zn7WpF2O18qtfTGAPQC_UNoHsVPZ-Nry5aNzFxQpoXDgziIcjQWEpI8OEUIyJQhl2jS6-VKJMINSWDqb2mARvTSuLd8eG_4tw5yMQFvKikjcbCdx0gqnbXu4dHTInGgtnozyY9b2HRx6Qk0wpQ-OsYaYskZFv8eP8pFEuOy-S65Uyhhbt0f5FuRWPTL0lOAGpPTYFOt0g6niq-ryXC2nQ"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "RSA",
                      "e": "AQAB",
                      "n": "lqF6-rWlBHPB7fEGQ46iKBFplLY5qJaWX1kH0bcUmQMgjsVWlOpNb6I9NTeuSf3JM54vDS_8iZvmJ7bsQOWBCZEv_rWW4kMJSjcoAdhDt_5sU3g2mFbv7KLRpsfWSN8G4zn7WpF2O18qtfTGAPQC_UNoHsVPZ-Nry5aNzFxQpoXDgziIcjQWEpI8OEUIyJQhl2jS6-VKJMINSWDqb2mARvTSuLd8eG_4tw5yMQFvKikjcbCdx0gqnbXu4dHTInGgtnozyY9b2HRx6Qk0wpQ-OsYaYskZFv8eP8pFEuOy-S65Uyhhbt0f5FuRWPTL0lOAGpPTYFOt0g6niq-ryXC2nQ",
                      "d": "X4UBLnD3tu4NIW1Bcp_FdrEsCdDQmXb83nPfwH5fwnQ4NjEvqXk3J75zIAcyL9uOtnvuDGfMthq1haO7B6BCBqYaEGRozQyDnJuDdEAHGWtumDPYMxyWQrIxTpjU6xr7DCbdnN43YokD1aTl1v7l0mLnaPPoWdHerpjHTLuRrTaWdg8822HzDi4AQddA9aAq78ijX8WCKvJGzqA7WqUikL8veSnXvbFpZaU1_XKzDLdP3oTp3uZMcvbEgCbh1UYxorlBe6S6H-BM0PHG4AOdpGYgDvCSqb_acAdLZQBpoqiNV0jC3PBVtb-GgOFhdvFvgEC-KBwqAUiyJin1iCpy4Q"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.RSA;
	}

	@Override
	List<String> getAlgorithms() {
		return Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.PS256);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_RSAPrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_RSAPublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		RSAPublicKey publicKey = JWK_to_PublicKey.JWK_to_RSAPublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.RSAPublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 294);

		RSAPublicKey publicKey2 = PublicKeyBytes.bytes_to_RSAPublicKey(publicKeyBytes);
		assertArrayEquals(publicKey.getEncoded(), publicKey2.getEncoded());
		JWK jwk2 = PublicKey_to_JWK.RSAPublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		KeyPair privateKey = JWK_to_PrivateKey.JWK_to_RSAPrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.RSAPrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 1289);

		KeyPair privateKey2 = PrivateKeyBytes.bytes_to_RSAPrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey.getPrivate().getEncoded(), privateKey2.getPrivate().getEncoded());
		JWK jwk2 = PrivateKey_to_JWK.RSAPrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
