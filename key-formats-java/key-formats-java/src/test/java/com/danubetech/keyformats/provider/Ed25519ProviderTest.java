package com.danubetech.keyformats.provider;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumEd25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import com.goterl.lazysodium.SodiumJava;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class Ed25519ProviderTest {

	static boolean isSodiumInstalled() {
		try {
			new SodiumJava();
			return true;
		} catch (UnsatisfiedLinkError ex) {
			return false;
		}
	}

	@Test
	public void testNaClSodiumEd25519Provider() throws Exception {
		if (! Ed25519ProviderTest.isSodiumInstalled()) {
			System.out.println("libsodium is not installed. Skipping.");
			return;
		}
		this.internalTest(new NaClSodiumEd25519Provider());
	}

	@Test
	public void testTinkEd25519Provider() throws Exception {
		this.internalTest(new TinkEd25519Provider());
	}

	private void internalTest(Ed25519Provider ed25519Provider) throws Exception {
		byte[] zeros = new byte[64];
		Arrays.fill(zeros, (byte) 0);
		byte[] publicKey = new byte[32];
		byte[] privateKey = new byte[64];
		byte[] seed = "00000000000000000000000000000000".getBytes(StandardCharsets.US_ASCII);
		ed25519Provider.generateEC25519KeyPairFromSeed(publicKey, privateKey, seed);
		assertFalse(Arrays.equals(publicKey, zeros));
		assertFalse(Arrays.equals(privateKey, zeros));
		assertArrayEquals(publicKey, Hex.decodeHex("1ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137".toCharArray()));
		assertArrayEquals(privateKey, Hex.decodeHex("30303030303030303030303030303030303030303030303030303030303030301ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137".toCharArray()));
		byte[] content1 = "Hello World".getBytes(StandardCharsets.UTF_8);
		byte[] content2 = "Other Content".getBytes(StandardCharsets.UTF_8);
		byte[] signature1 = ed25519Provider.sign(content1, privateKey);
		byte[] signature2 = ed25519Provider.sign(content2, privateKey);
		assertEquals(64, signature1.length);
		assertEquals(64, signature2.length);
		assertFalse(Arrays.equals(signature1, signature2));
		assertFalse(Arrays.equals(signature1, zeros));
		assertFalse(Arrays.equals(signature2, zeros));
		assertArrayEquals(signature1, Hex.decodeHex("7aca1002fb51bba33e6555ef843c5885f39cc07f9eb9407ab6f6fe2d8d38befd80e6a873ce7b390f2e2b953a3b96103a07a4c613c3a694be8ed9ace6dd8d9e03".toCharArray()));
		assertArrayEquals(signature2, Hex.decodeHex("5bc1ce8845815a87e9b220534ebc847befff73746649380658923c16700958d206db17704511c0b2c5546d8ee842d6de997e40d7e856592b574a8bfcafda0007".toCharArray()));
		boolean verifiedTrue1 = ed25519Provider.verify(content1, signature1, publicKey);
		boolean verifiedTrue2 = ed25519Provider.verify(content2, signature2, publicKey);
		assertTrue(verifiedTrue1);
		assertTrue(verifiedTrue2);
		boolean verifiedFalse1 = ed25519Provider.verify(content1, signature2, publicKey);
		boolean verifiedFalse2 = ed25519Provider.verify(content2, signature1, publicKey);
		assertFalse(verifiedFalse1);
		assertFalse(verifiedFalse2);
	}
}
