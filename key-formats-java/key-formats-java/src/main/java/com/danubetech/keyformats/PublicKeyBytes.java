package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.util.ByteArrayUtil;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

public class PublicKeyBytes {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/*
	 * RSA
	 */

	public static byte[] RSAPublicKey_to_bytes(RSAPublicKey publicKey) {

		return publicKey.getEncoded();
	}

	public static RSAPublicKey bytes_to_RSAPublicKey(byte[] publicKeyBytes) {

		RSAPublicKey publicKey;
		try {
			publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
		return publicKey;
	}

	/*
	 * secp256k1
	 */

	public static byte[] secp256k1PublicKey_to_bytes(ECKey publicKey) {

		org.bouncycastle.math.ec.ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		byte[] x = publicKeyPoint.getAffineXCoord().getEncoded();
		if (x.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length);
		byte[] y = publicKeyPoint.getAffineYCoord().getEncoded();
		if (y.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length);

		byte[] publicKeyBytes = new byte[65];
		publicKeyBytes[0] = 4;
		System.arraycopy(x, 0, publicKeyBytes, 1, 32);
		System.arraycopy(y, 0, publicKeyBytes, 33, 32);

		return publicKeyBytes;
	}

	public static ECKey bytes_to_secp256k1PublicKey(byte[] publicKeyBytes) {

		return ECKey.fromPublicOnly(publicKeyBytes);
	}

	/*
	 * Bls12381G1
	 */

	public static byte[] Bls12381G1PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls12381G1PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls12381G2
	 */

	public static byte[] Bls12381G2PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls12381G2PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls48581G1
	 */

	public static byte[] Bls48581G1PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls48581G1PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls48581G2
	 */

	public static byte[] Bls48581G2PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls48581G2PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Ed25519
	 */

	public static byte[] Ed25519PublicKey_to_bytes(byte[] publicKey) {

		return publicKey;
	}

	public static byte[] bytes_to_Ed25519PublicKey(byte[] publicKeyBytes) {

		return publicKeyBytes;
	}

	/*
	 * X25519
	 */

	public static byte[] X25519PublicKey_to_bytes(byte[] publicKey) {

		return publicKey;
	}

	public static byte[] bytes_to_X25519PublicKey(byte[] publicKeyBytes) {

		return publicKeyBytes;
	}

	/*
	 * P-256
	 */

	public static byte[] P_256PublicKey_to_bytes(ECPublicKey publicKey) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");

		byte[] publicKeyBytes = new byte[1+x.length+y.length];
		publicKeyBytes[0] = 4;
		System.arraycopy(x, 0, publicKeyBytes, 1, x.length);
		System.arraycopy(y, 0, publicKeyBytes, 1+x.length, y.length);

		return publicKeyBytes;
	}

	public static ECPublicKey bytes_to_P_256PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 65) throw new IllegalArgumentException("Expected 65 bytes instead of " + publicKeyBytes.length);

		byte[] x = new byte[32];
		byte[] y = new byte[32];
		if (publicKeyBytes[0] != 4) throw new IllegalArgumentException("Expected 0x04 as first byte instead of " + publicKeyBytes[0] + " (length: " + publicKeyBytes.length + ")");
		System.arraycopy(publicKeyBytes, 1, x, 0, x.length);
		System.arraycopy(publicKeyBytes, 1+x.length, y, 0, y.length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	/*
	 * P-384
	 */

	public static byte[] P_384PublicKey_to_bytes(ECPublicKey publicKey) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length != 48) throw new IllegalArgumentException("Invalid 'x' value (not 48 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length != 48) throw new IllegalArgumentException("Invalid 'y' value (not 48 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");

		byte[] publicKeyBytes = new byte[1+x.length+y.length];
		publicKeyBytes[0] = 4;
		System.arraycopy(x, 0, publicKeyBytes, 1, x.length);
		System.arraycopy(y, 0, publicKeyBytes, 1+x.length, y.length);

		return publicKeyBytes;
	}

	public static ECPublicKey bytes_to_P_384PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 97) throw new IllegalArgumentException("Expected 97 bytes instead of " + publicKeyBytes.length);

		byte[] x = new byte[48];
		byte[] y = new byte[48];
		if (publicKeyBytes[0] != 4) throw new IllegalArgumentException("Expected 0x04 as first byte instead of " + publicKeyBytes[0] + " (length: " + publicKeyBytes.length + ")");
		System.arraycopy(publicKeyBytes, 1, x, 0, x.length);
		System.arraycopy(publicKeyBytes, 1+x.length, y, 0, y.length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	/*
	 * P-521
	 */

	public static byte[] P_521PublicKey_to_bytes(ECPublicKey publicKey) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length < 64 || x.length > 66) throw new IllegalArgumentException("Invalid 'x' value (<64 or >66 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length < 64 || y.length > 66) throw new IllegalArgumentException("Invalid 'y' value (<64 or >66 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");

		byte[] publicKeyBytes = new byte[1+x.length+y.length];
		publicKeyBytes[0] = 4;
		System.arraycopy(x, 0, publicKeyBytes, 1, x.length);
		System.arraycopy(y, 0, publicKeyBytes, 1+x.length, y.length);

		return publicKeyBytes;
	}

	public static ECPublicKey bytes_to_P_521PublicKey(byte[] publicKeyBytes) {

		if (! (publicKeyBytes.length >= 129 && publicKeyBytes.length <= 133)) throw new IllegalArgumentException("Expected >=129 and <=133 bytes instead of " + publicKeyBytes.length);

		byte[] x = new byte[(publicKeyBytes.length-1)/2];
		byte[] y = new byte[(publicKeyBytes.length-1)/2];
		if (publicKeyBytes[0] != 4) throw new IllegalArgumentException("Expected 0x04 as first byte instead of " + publicKeyBytes[0] + " (length: " + publicKeyBytes.length + ")");
		System.arraycopy(publicKeyBytes, 1, x, 0, x.length);
		System.arraycopy(publicKeyBytes, 1+x.length, y, 0, y.length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}
}
