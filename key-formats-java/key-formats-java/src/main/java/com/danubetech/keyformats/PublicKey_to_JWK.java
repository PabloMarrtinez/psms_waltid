package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.util.ByteArrayUtil;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;

public class PublicKey_to_JWK {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static JWK RSAPublicKey_to_JWK(RSAPublicKey publicKey, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.RSA);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(publicKey.getModulus())));
		jsonWebKey.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(publicKey.getPublicExponent())));

		return jsonWebKey;
	}

	public static JWK secp256k1PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		org.bouncycastle.math.ec.ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineXCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineYCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.secp256k1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jsonWebKey;
	}

	public static JWK Bls12381G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls48581G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls48581G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls48581G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls48581G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Ed25519PublicKey_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Ed25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK X25519PublicKey_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.X25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK P_256PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

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

		return jsonWebKey;
	}

	public static JWK P_384PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

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

		return jsonWebKey;
	}

	public static JWK P_521PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length < 64 || x.length > 66) throw new IllegalArgumentException("Invalid 'x' value (<64 or >66 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		x = ByteArrayUtil.padArrayZeros(x, 66);
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length < 64 || y.length > 66) throw new IllegalArgumentException("Invalid 'y' value (<64 or >66 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");
		y = ByteArrayUtil.padArrayZeros(y, 66);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_521);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jsonWebKey.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));

		return jsonWebKey;
	}

	/*
	 * Convenience methods
	 */

	public static JWK RSAPublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return RSAPublicKey_to_JWK(PublicKeyBytes.bytes_to_RSAPublicKey(publicKeyBytes), kid, use);
	}

	public static JWK secp256k1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return secp256k1PublicKey_to_JWK(PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls12381G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls12381G1PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls12381G1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls12381G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls12381G2PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls12381G2PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls48581G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls48581G1PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls48581G1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls48581G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls48581G2PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls48581G2PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Ed25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Ed25519PublicKey_to_JWK(PublicKeyBytes.bytes_to_Ed25519PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK X25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return X25519PublicKey_to_JWK(PublicKeyBytes.bytes_to_X25519PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_256PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_256PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_256PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_384PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_384PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_384PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_521PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_521PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_521PublicKey(publicKeyBytes), kid, use);
	}
}
