package com.danubetech.keyformats.crypto.provider;

import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.ServiceLoader;

public abstract class Ed25519Provider {

	private static Ed25519Provider instance;

	public static Ed25519Provider get() {

		Ed25519Provider result = instance;

		if (result == null) {

			synchronized(Ed25519Provider.class) {

				result = instance;

				if (result == null) {

					ServiceLoader<Ed25519Provider> serviceLoader = ServiceLoader.load(Ed25519Provider.class, Ed25519Provider.class.getClassLoader());
					Iterator<Ed25519Provider> iterator = serviceLoader.iterator();
					if (! iterator.hasNext()) throw new RuntimeException("No " + Ed25519Provider.class.getName() + " registered");

					instance = result = iterator.next();
				}
			}
		}

		return result;
	}

	public static void set(Ed25519Provider instance) {

		Ed25519Provider.instance = instance;
	}

	/**
	 * Generate a new Ed25519 private/public key pair.
	 * @param publicKey A 32 byte array that will be filled with the new Ed25519 public key.
	 * @param privateKey A 64 byte array that will be filled with the new Ed25519 private key concatenated with the new Ed25519 public key.
	 */
	public abstract void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException;

	/**
	 * Generate a new Ed25519 private/public key pair using a seed.
	 * @param publicKey A 32 byte array that will be filled with the new Ed25519 public key.
	 * @param privateKey A 64 byte array that will be filled with the new Ed25519 private key concatenated with the new Ed25519 public key.
	 * @param seed A seed byte array for generating the new Ed25519 private/public key pair.
	 */
	public abstract void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws GeneralSecurityException;

	/**
	 * Sign content using an Ed25519 private key.
	 * @param content The content to sign.
	 * @param privateKey A 64 byte array containing a Ed25519 private key concatenated with a Ed25519 public key.
	 * @return A 64 byte array containing the signature.
	 */
	public abstract byte[] sign(byte[] content, byte[] privateKey) throws GeneralSecurityException;

	/**
	 * Verify a signature against given content using an Ed25519 public key.
	 * @param content The signed content.
	 * @param signature The signature.
	 * @param publicKey A 32 byte array containing an Ed25519 public key.
	 * @return True if the signature can be verified, false otherwise.
	 */
	public abstract boolean verify(byte[] content, byte[] signature, byte[] publicKey) throws GeneralSecurityException;
}
