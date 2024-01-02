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

import static org.junit.jupiter.api.Assertions.*;

public class P_521Test extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-521",
                      "x": "ACvIr_udUJF1StwVRFG36Nh4uaXANQcv5wBr5NvTfmIp9DM70vPtWFlXHZD2Ck1Fm6QfKnjoSF-wSBTWW3I_GLQx",
                      "y": "AGQKM2hWzUp1HWEv7-gOYQBHwkT6Mc8-2dSVifBrjGPiPGC14iMSFEP9RXI9SeiBG64NFI30eYovMofgCuJvlx9M"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty": "EC",
                      "crv": "P-521",
                      "x": "ACvIr_udUJF1StwVRFG36Nh4uaXANQcv5wBr5NvTfmIp9DM70vPtWFlXHZD2Ck1Fm6QfKnjoSF-wSBTWW3I_GLQx",
                      "y": "AGQKM2hWzUp1HWEv7-gOYQBHwkT6Mc8-2dSVifBrjGPiPGC14iMSFEP9RXI9SeiBG64NFI30eYovMofgCuJvlx9M",
                      "d": "AIU2LKboudbyA001rYZSngUhKfDT2V4HH-c_rzSBh7niBNKPcRfnAWunVg30lD9TRPuDsM8UL6Q7J3k7r23GJ2cc"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.P_521;
	}

	@Override
	List<String> getAlgorithms() {
		return Collections.singletonList(JWSAlgorithm.ES512);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_P_521PrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_P_521PublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		ECPublicKey publicKey = JWK_to_PublicKey.JWK_to_P_521PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.P_521PublicKey_to_bytes(publicKey);
		assertTrue(publicKeyBytes.length >= 129 && publicKeyBytes.length <= 133);

		ECPublicKey publicKey2 = PublicKeyBytes.bytes_to_P_521PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey.getEncoded(), publicKey2.getEncoded());
		JWK jwk2 = PublicKey_to_JWK.P_521PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		ECPrivateKey privateKey = JWK_to_PrivateKey.JWK_to_P_521PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.P_521PrivateKey_to_bytes(privateKey);
		assertTrue(privateKeyBytes.length >= 64 && privateKeyBytes.length <= 66);

		ECPrivateKey privateKey2 = PrivateKeyBytes.bytes_to_P_521PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey.getEncoded(), privateKey2.getEncoded());
		JWK jwk2 = PrivateKey_to_JWK.P_521PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
