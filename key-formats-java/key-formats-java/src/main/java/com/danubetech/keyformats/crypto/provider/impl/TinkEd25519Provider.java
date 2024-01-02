package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;

import java.security.GeneralSecurityException;

public class TinkEd25519Provider extends Ed25519Provider {

	public static final int SEED_LEN = 32;

	static {
		try {
			SignatureConfig.register();
		} catch (GeneralSecurityException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Ed25519Sign.SECRET_KEY_LEN + Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid public key length: "+ publicKey.length);

		// create key pair

		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();

		System.arraycopy(tinkKeyPair.getPrivateKey(), 0, privateKey, 0, Ed25519Sign.SECRET_KEY_LEN);
		System.arraycopy(tinkKeyPair.getPublicKey(), 0, publicKey, 0, Ed25519Verify.PUBLIC_KEY_LEN);
		System.arraycopy(publicKey, 0, privateKey, Ed25519Verify.PUBLIC_KEY_LEN, Ed25519Verify.PUBLIC_KEY_LEN);
	}

	@Override
	public void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws GeneralSecurityException {

		if (privateKey.length != Ed25519Sign.SECRET_KEY_LEN + Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid public key length: "+ publicKey.length);
		if (seed.length != SEED_LEN) throw new GeneralSecurityException("Invalid seed length: "+ publicKey.length);

		// create key pair

		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed);

		System.arraycopy(tinkKeyPair.getPrivateKey(), 0, privateKey, 0, Ed25519Sign.SECRET_KEY_LEN);
		System.arraycopy(tinkKeyPair.getPublicKey(), 0, publicKey, 0, Ed25519Verify.PUBLIC_KEY_LEN);
		System.arraycopy(publicKey, 0, privateKey, Ed25519Verify.PUBLIC_KEY_LEN, Ed25519Verify.PUBLIC_KEY_LEN);
	}

	@Override
	public byte[] sign(byte[] content, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Ed25519Sign.SECRET_KEY_LEN + Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);

		byte[] privateKeyOnly = new byte[32];
		System.arraycopy(privateKey, 0, privateKeyOnly, 0, Ed25519Sign.SECRET_KEY_LEN);

		byte[] signatureValue = new Ed25519Sign(privateKeyOnly).sign(content);

		return signatureValue;
	}

	@Override
	public boolean verify(byte[] content, byte[] signature, byte[] publicKey) throws GeneralSecurityException {

		if (signature.length != Ed25519Verify.SIGNATURE_LEN) throw new GeneralSecurityException("Invalid signature length: " + signature.length);
		if (publicKey.length != Ed25519Verify.PUBLIC_KEY_LEN) throw new GeneralSecurityException("Invalid public key length: "+ publicKey.length);

		try {

			new Ed25519Verify(publicKey).verify(signature, content);
		} catch (GeneralSecurityException ex) {
			return false;
		}

		return true;
	}
}
