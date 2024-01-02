package com.danubetech.keyformats;

import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.util.ByteArrayUtil;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;

public class PrivateKey_to_JWK {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static JWK RSAPrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.RSA);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPublicKey) privateKey.getPublic()).getModulus())));
		jsonWebKey.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPublicKey) privateKey.getPublic()).getPublicExponent())));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPrivateKey) privateKey.getPrivate()).getPrivateExponent())));

		return jsonWebKey;
	}

	public static JWK secp256k1PrivateKey_to_JWK(ECKey privateKey, String kid, String use) {

		org.bouncycastle.math.ec.ECPoint publicKeyPoint = privateKey.getPubKeyPoint();
		byte[] privateKeyBytes = privateKey.getPrivKeyBytes();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineXCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineYCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid 'd' value (not 32 bytes): length=" + privateKeyBytes.length);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.secp256k1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineYCoord().getEncoded()));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G1PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G2PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls48581G1PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls48581G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls48581G2PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls48581G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Ed25519PrivateKey_to_JWK(byte[] privateKeyBytes, String kid, String use) {

		byte[] publicKeyBytes = Arrays.copyOfRange(privateKeyBytes, 32, 64);
		byte[] onlyPrivateKeyBytes = Arrays.copyOfRange(privateKeyBytes, 0, 32);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Ed25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(onlyPrivateKeyBytes));

		return jsonWebKey;
	}

	public static JWK X25519PrivateKey_to_JWK(byte[] privateKeyBytes, String kid, String use) {

		byte[] publicKeyBytes = Arrays.copyOfRange(privateKeyBytes, 32, 64);
		byte[] onlyPrivateKeyBytes = Arrays.copyOfRange(privateKeyBytes, 0, 32);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.X25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(onlyPrivateKeyBytes));

		return jsonWebKey;
	}

	public static JWK P_256PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length != 32) throw new IllegalArgumentException("Invalid 'd' value (not 32 bytes): " + new String(Hex.encodeHex(d)) + ", length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_256);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jsonWebKey;
	}

	public static JWK P_384PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length != 48) throw new IllegalArgumentException("Invalid 'd' value (not 48 bytes): " + new String(Hex.encodeHex(d)) + ", length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp384r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length != 48) throw new IllegalArgumentException("Invalid 'x' value (not 48 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length != 48) throw new IllegalArgumentException("Invalid 'y' value (not 48 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_384);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jsonWebKey;
	}

	public static JWK P_521PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length != 64 && d.length != 65 && d.length != 66) throw new IllegalArgumentException("Invalid 'd' value (not 64 or 65 or 66 bytes): " + new String(Hex.encodeHex(d)) + ", length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");
		d = ByteArrayUtil.padArrayZeros(d, 66);

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp521r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length != 64 && x.length != 65 && x.length != 66) throw new IllegalArgumentException("Invalid 'x' value (not 64 or 65 or bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		x = ByteArrayUtil.padArrayZeros(x, 66);
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length != 64 && y.length != 65 && y.length != 66) throw new IllegalArgumentException("Invalid 'y' value (not 64 or 65 or 66 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");
		y = ByteArrayUtil.padArrayZeros(y, 66);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_521);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));
		jsonWebKey.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jsonWebKey;
	}

	/*
	 * Convenience methods
	 */

	public static JWK RSAPrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return RSAPrivateKey_to_JWK(PrivateKeyBytes.bytes_to_RSAPrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK secp256k1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return secp256k1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_secp256k1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls12381G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls12381G1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls12381G1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls12381G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls12381G2PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls12381G2PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls48581G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls48581G1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls48581G1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls48581G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls48581G2PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls48581G2PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Ed25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Ed25519PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Ed25519PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK X25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return X25519PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_X25519PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_256PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_256PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_256PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_384PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_384PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_384PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_521PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_521PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_521PrivateKey(privateKeyBytes), kid, use);
	}
}
