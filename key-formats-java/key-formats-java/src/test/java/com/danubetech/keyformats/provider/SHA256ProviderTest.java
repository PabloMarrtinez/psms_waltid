package com.danubetech.keyformats.provider;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumSHA256Provider;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SHA256ProviderTest {

	@Test
	public void testNaClSodiumSHA256Provider() throws Exception {
		if (! Ed25519ProviderTest.isSodiumInstalled()) {
			System.out.println("libsodium is not installed. Skipping.");
			return;
		}
		this.internalTest(new NaClSodiumSHA256Provider());
	}

	@Test
	public void testJavaSHA256Provider() throws Exception {
		this.internalTest(new JavaSHA256Provider());
	}

	private void internalTest(SHA256Provider sha256Provider) throws Exception {
		byte[] zeros = new byte[256];
		Arrays.fill(zeros, (byte) 0);
		byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);
		byte[] sha256 = sha256Provider.sha256(content);
		assertEquals(sha256.length, 32);
		assertFalse(Arrays.equals(sha256, zeros));
		assertArrayEquals(sha256, Hex.decodeHex("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e".toCharArray()));
	}
}
