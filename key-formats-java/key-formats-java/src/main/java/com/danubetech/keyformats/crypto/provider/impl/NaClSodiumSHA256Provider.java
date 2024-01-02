package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Hash;

import java.security.GeneralSecurityException;

public class NaClSodiumSHA256Provider extends SHA256Provider {

	private static final LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());
	private static final Hash.Native hashNative = lazySodium;

	@Override
	public byte[] sha256(byte[] bytes) throws GeneralSecurityException {
		byte[] buffer = new byte[32];
		hashNative.cryptoHashSha256(buffer, bytes, bytes.length);
		return buffer;
	}
}
