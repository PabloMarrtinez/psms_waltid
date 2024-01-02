package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTest {

	abstract KeyTypeName getKeyTypeName();
	abstract List<String> getAlgorithms();
	abstract Object getPrivateKey();
	abstract Object getPublicKey();

	protected byte[] getContent() {
		return "Hello World".getBytes(StandardCharsets.UTF_8);
	}

	@Test
	public void testSignVerify() throws Exception {
		for (String algorithm : this.getAlgorithms()) {
			PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(this.getKeyTypeName(), algorithm, this.getPrivateKey());
			byte[] signature = privateKeySigner.sign(this.getContent(), algorithm);
			PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(this.getKeyTypeName(), algorithm, this.getPublicKey());
			boolean verified = publicKeyVerifier.verify(this.getContent(), signature, algorithm);
			assertTrue(verified);
		}
	}
}
