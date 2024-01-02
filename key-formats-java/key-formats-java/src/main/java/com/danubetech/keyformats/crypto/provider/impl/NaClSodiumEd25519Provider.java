package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Sign;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public class NaClSodiumEd25519Provider extends Ed25519Provider {

	private static final LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());
	private static final Sign.Native signNative = lazySodium;

	@Override
	public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sign.ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Sign.ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: " + publicKey.length);

		// create seed

		byte[] seed = RandomProvider.get().randomBytes(256);
		seed = SHA256Provider.get().sha256(seed);

		// create key pair

		signNative.cryptoSignSeedKeypair(publicKey, privateKey, seed);
		System.arraycopy(publicKey, 0, privateKey, Sign.ED25519_PUBLICKEYBYTES, Sign.ED25519_PUBLICKEYBYTES);
	}

	@Override
	public void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws GeneralSecurityException {

		if (privateKey.length != Sign.ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Sign.ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: " + publicKey.length);
		if (seed.length != Sign.ED25519_SEEDBYTES) throw new GeneralSecurityException("Invalid seed length: "+ publicKey.length);

		// create key pair

		signNative.cryptoSignSeedKeypair(publicKey, privateKey, seed);
		System.arraycopy(publicKey, 0, privateKey, Sign.ED25519_PUBLICKEYBYTES, Sign.ED25519_PUBLICKEYBYTES);
	}

	@Override
	public byte[] sign(byte[] content, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sign.ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);

		byte[] signatureValue = new byte[Sign.ED25519_BYTES + content.length];
		Arrays.fill(signatureValue, 0, Sign.ED25519_BYTES, (byte) 0);
		System.arraycopy(content, 0, signatureValue, Sign.ED25519_BYTES, content.length);

		boolean ret = signNative.cryptoSign(signatureValue, content, content.length, privateKey);
		if (! ret) throw new GeneralSecurityException("Unknown signing error");

		signatureValue = Arrays.copyOfRange(signatureValue, 0, Sign.ED25519_BYTES);

		return signatureValue;
	}

	@Override
	public boolean verify(byte[] content, byte[] signature, byte[] publicKey) throws GeneralSecurityException {

		if (signature.length != Sign.ED25519_BYTES) throw new GeneralSecurityException("Invalid signature length: " + signature.length);
		if (publicKey.length != Sign.ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: " + publicKey.length);

		byte[] sigAndMsg = new byte[signature.length + content.length];
		System.arraycopy(signature, 0, sigAndMsg, 0, signature.length);
		System.arraycopy(content, 0, sigAndMsg, signature.length, content.length);

		byte[] buffer = new byte[sigAndMsg.length];

		boolean ret = signNative.cryptoSignOpen(buffer, sigAndMsg, sigAndMsg.length, publicKey);
		if (! ret) return false;

		buffer = Arrays.copyOf(buffer, buffer.length - Sign.ED25519_BYTES);

		return Arrays.equals(content, buffer);
	}
}
