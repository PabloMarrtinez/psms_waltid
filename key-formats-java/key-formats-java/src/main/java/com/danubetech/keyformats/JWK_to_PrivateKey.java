package com.danubetech.keyformats;

import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import com.fasterxml.jackson.core.JsonProcessingException;
import inf.um.model.attributes.Attribute;
import inf.um.model.attributes.AttributeDefinition;
import inf.um.model.attributes.AttributeDefinitionString;
import inf.um.multisign.MSprivateKey;
import inf.um.pairingBLS461.PairingBuilderBLS461;
import inf.um.pairingBLS461.ZpElementBLS461;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.protos.PabcSerializer;
import inf.um.psmultisign.PSprivateKey;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;

import java.util.Base64;
import org.json.JSONObject;
import org.miracl.core.BLS12461.BIG;

import java.util.HashMap;
import java.util.Map;
import com.google.protobuf.ByteString;
import inf.um.pairingBLS461.ZpElementBLS461;
import inf.um.protos.PabcSerializer;

public class JWK_to_PrivateKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static Object JWK_to_anyPrivateKey(JWK jsonWebKey) {


		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jsonWebKey);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls12381G1)
			return JWK_to_Bls12381G1PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls12381G2)
			return JWK_to_Bls12381G2PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls48581G1)
			return JWK_to_Bls12381G1PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls48581G2)
			return JWK_to_Bls12381G2PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.P_256)
			return JWK_to_P_256PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.P_384)
			return JWK_to_P_384PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.PsmsBlsSignature2022)
			return JWK_to_PsmsBlsPrivateKey(jsonWebKey);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}
	

	public static KeyPair JWK_to_RSAPrivateKey(JWK jsonWebKey) {

		if (! KeyType.RSA.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, jsonWebKey.getNdecoded()), new BigInteger(1, jsonWebKey.getDdecoded()));
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(1, jsonWebKey.getNdecoded()), new BigInteger(1, jsonWebKey.getEdecoded()));
			return new KeyPair(keyFactory.generatePublic(rsaPublicKeySpec), keyFactory.generatePrivate(rsaPrivateKeySpec));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	public static ECKey JWK_to_secp256k1PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return ECKey.fromPrivate(jsonWebKey.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls12381G1PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls12381G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new bbs.signatures.KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls12381G2PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls12381G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new bbs.signatures.KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls48581G1PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls48581G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new bbs.signatures.KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls48581G2PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls48581G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new bbs.signatures.KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static byte[] JWK_to_Ed25519PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Ed25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(jsonWebKey.getDdecoded(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(jsonWebKey.getXdecoded(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}

	public static byte[] JWK_to_X25519PrivateKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.X25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(jsonWebKey.getDdecoded(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(jsonWebKey.getXdecoded(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}

	public static ECPrivateKey JWK_to_P_256PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_256.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] d = jsonWebKey.getDdecoded();
		if (d.length != 32) throw new IllegalArgumentException("Invalid 'd' value (not 32 bytes): " + jsonWebKey.getD() + ", length=" + jsonWebKey.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	public static ECPrivateKey JWK_to_P_384PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_384.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] d = jsonWebKey.getDdecoded();
		if (d.length != 48) throw new IllegalArgumentException("Invalid 'd' value (not 48 bytes): " + jsonWebKey.getD() + ", length=" + jsonWebKey.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	public static ECPrivateKey JWK_to_P_521PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_521.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] d = jsonWebKey.getDdecoded();
		if (d.length != 66) throw new IllegalArgumentException("Invalid 'd' value (not 66 bytes): " + jsonWebKey.getD() + ", length=" + jsonWebKey.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}


	public static MSprivateKey JWK_to_PsmsBlsPrivateKey(JWK jsonWebKey) {
		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! (Curve.PSMS.equals(jsonWebKey.getCrv()) || Curve.PSMSPROOF.equals(jsonWebKey.getCrv())))  throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] decode_bytes_x = Base64.getDecoder().decode(jsonWebKey.getX());
		ByteString byteString_x = ByteString.copyFrom(decode_bytes_x);
		PabcSerializer.ZpElement zpElementProto_x = PabcSerializer.ZpElement.newBuilder()
				.setX(byteString_x)
				.build();
		ZpElementBLS461 zpElement_x = new ZpElementBLS461(zpElementProto_x);


		byte[] decode_bytes_ym = Base64.getDecoder().decode(jsonWebKey.getY_m());
		ByteString byteString_ym = ByteString.copyFrom(decode_bytes_ym);
		PabcSerializer.ZpElement zpElementProto_ym = PabcSerializer.ZpElement.newBuilder()
				.setX(byteString_ym)
				.build();
		ZpElementBLS461 zpElement_ym = new ZpElementBLS461(zpElementProto_ym);


		byte[] decode_bytes_epoch = Base64.getDecoder().decode(jsonWebKey.getEpoch());
		ByteString byteString_epoch = ByteString.copyFrom(decode_bytes_epoch);
		PabcSerializer.ZpElement zpElementProto_epoch = PabcSerializer.ZpElement.newBuilder()
				.setX(byteString_epoch)
				.build();
		ZpElementBLS461 zp_epoch = new ZpElementBLS461(zpElementProto_epoch);

		JSONObject jsonObject = new JSONObject(jsonWebKey.getY());
		Map<String, ZpElement> y_zp = new HashMap<>();

		// Creacion de mapa ID -> valor base64
		jsonObject.keys().forEachRemaining(key -> {
			String encodedValue = jsonObject.getString(key);
			byte[] decodedBytes = Base64.getDecoder().decode(encodedValue);
			ByteString b = ByteString.copyFrom(decodedBytes);
			PabcSerializer.ZpElement zp_seriealizer = PabcSerializer.ZpElement.newBuilder()
					.setX(b)
					.build();
			ZpElementBLS461 zp = new ZpElementBLS461(zp_seriealizer);
			y_zp.put(key,zp);
		});

		return new PSprivateKey(zpElement_x, zpElement_ym, y_zp, zp_epoch);
	}


	/*
	 * Convenience methods
	 */

	public static byte[] JWK_to_RSAPrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.RSAPrivateKey_to_bytes(JWK_to_RSAPrivateKey(jwk));
	}

	public static byte[] JWK_to_secp256k1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.secp256k1PrivateKey_to_bytes(JWK_to_secp256k1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls12381G1PrivateKey_to_bytes(JWK_to_Bls12381G1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G2PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls12381G2PrivateKey_to_bytes(JWK_to_Bls12381G2PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls48581G1PrivateKey_to_bytes(JWK_to_Bls48581G1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G2PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls48581G2PrivateKey_to_bytes(JWK_to_Bls48581G2PrivateKey(jwk));
	}

	public static byte[] JWK_to_Ed25519PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Ed25519PrivateKey_to_bytes(JWK_to_Ed25519PrivateKey(jwk));
	}

	public static byte[] JWK_to_X25519PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.X25519PrivateKey_to_bytes(JWK_to_X25519PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_256PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_256PrivateKey_to_bytes(JWK_to_P_256PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_384PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_384PrivateKey_to_bytes(JWK_to_P_384PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_521PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_521PrivateKey_to_bytes(JWK_to_P_521PrivateKey(jwk));
	}
}
