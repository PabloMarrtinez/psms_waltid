package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Random;

import java.security.GeneralSecurityException;

public class NaClSodiumRandomProvider extends RandomProvider {

	private static final LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());
	private static final Random random = lazySodium;

	@Override
	public byte[] randomBytes(int length) throws GeneralSecurityException {
		return random.randomBytesBuf(length);
	}
}
