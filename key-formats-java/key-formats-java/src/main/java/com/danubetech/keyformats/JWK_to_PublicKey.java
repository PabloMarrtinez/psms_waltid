package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import inf.um.pairingBLS461.ZpElementBLS461;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.protos.PabcSerializer;
import inf.um.pairingBLS461.Group1ElementBLS461;
import inf.um.psmultisign.PSverfKey;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import org.json.JSONObject;
import java.util.HashMap;
import java.util.Map;

import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
public class JWK_to_PublicKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static Object JWK_to_anyPublicKey(JWK jsonWebKey) {

		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jsonWebKey);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls12381G1)
			return JWK_to_Bls12381G1PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls12381G2)
			return JWK_to_Bls12381G2PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls48581G1)
			return JWK_to_Bls48581G1PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.Bls48581G2)
			return JWK_to_Bls48581G2PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.P_256)
			return JWK_to_P_256PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.P_384)
			return JWK_to_P_384PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.P_521)
			return JWK_to_P_521PublicKey(jsonWebKey);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static RSAPublicKey JWK_to_RSAPublicKey(JWK jsonWebKey) {

		if (! KeyType.RSA.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(1, jsonWebKey.getNdecoded()), new BigInteger(1, jsonWebKey.getEdecoded()));
			return (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	public static ECKey JWK_to_secp256k1PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] x = jsonWebKey.getXdecoded();
		if (x.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + jsonWebKey.getX() + ", length=" + jsonWebKey.getXdecoded().length);
		byte[] y = jsonWebKey.getYdecoded();
		if (y.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + jsonWebKey.getY() + ", length=" + jsonWebKey.getYdecoded().length);

		byte[] publicKeyBytes = new byte[65];
		publicKeyBytes[0] = 4;
		System.arraycopy(x, 0, publicKeyBytes, 1, 32);
		System.arraycopy(y, 0, publicKeyBytes, 33, 32);

		return ECKey.fromPublicOnly(publicKeyBytes);
	}

	public static KeyPair JWK_to_Bls12381G1PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls12381G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), null);
	}

	public static KeyPair JWK_to_Bls12381G2PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls12381G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), null);
	}

	public static KeyPair JWK_to_Bls48581G1PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls48581G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), null);
	}

	public static KeyPair JWK_to_Bls48581G2PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Bls48581G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), null);
	}

	public static byte[] JWK_to_Ed25519PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Ed25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static byte[] JWK_to_X25519PublicKey(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.X25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static ECPublicKey JWK_to_P_256PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_256.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] x = jsonWebKey.getXdecoded();
		if (x.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + jsonWebKey.getX() + ", length=" + jsonWebKey.getXdecoded().length);
		byte[] y = jsonWebKey.getYdecoded();
		if (y.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + jsonWebKey.getY() + ", length=" + jsonWebKey.getYdecoded().length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	public static ECPublicKey JWK_to_P_384PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_384.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] x = jsonWebKey.getXdecoded();
		if (x.length != 48) throw new IllegalArgumentException("Invalid 'x' value (not 48 bytes): " + jsonWebKey.getX() + ", length=" + jsonWebKey.getXdecoded().length);
		byte[] y = jsonWebKey.getYdecoded();
		if (y.length != 48) throw new IllegalArgumentException("Invalid 'y' value (not 48 bytes): " + jsonWebKey.getY() + ", length=" + jsonWebKey.getYdecoded().length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	public static ECPublicKey JWK_to_P_521PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.P_521.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] x = jsonWebKey.getXdecoded();
		if (x.length != 66) throw new IllegalArgumentException("Invalid 'x' value (not 66 bytes): " + jsonWebKey.getX() + ", length=" + jsonWebKey.getXdecoded().length);
		byte[] y = jsonWebKey.getYdecoded();
		if (y.length != 66) throw new IllegalArgumentException("Invalid 'y' value (not 66 bytes): " + jsonWebKey.getY() + ", length=" + jsonWebKey.getYdecoded().length);

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}


	public static ECP createECPFromXY(JSONObject jsonObject) {
		// Convertir los arreglos de bytes a objetos BIG
		byte[] bytesx = Base64.getDecoder().decode(jsonObject.getString("x"));
		byte[] bytesy = Base64.getDecoder().decode(jsonObject.getString("y"));
		System.out.println(new String(bytesx));
		System.out.println(new String(bytesy));
		BIG x = BIG.fromBytes(bytesx);
		BIG y = BIG.fromBytes(bytesy);

		// Crear y retornar el objeto ECP
		return new ECP(x, y);
	}

	public static ECP createECPFromXY2(JSONObject jsonObject) {
		// Convertir los arreglos de bytes a objetos BIG
		byte[] bytesx = Base64.getDecoder().decode(jsonObject.getString("x"));
		byte[] bytesy = Base64.getDecoder().decode(jsonObject.getString("y"));
		System.out.println(new String(bytesx));
		System.out.println(new String(bytesy));
		BIG x = BIG.fromBytes(bytesx);
		BIG y = BIG.fromBytes(bytesy);

		// Crear y retornar el objeto ECP
		return new ECP(x, y);
	}

	/*
	public static PSverfKey JWK_to_Psms_PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.PSMS.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());





		String vx_x = new String(Base64.getDecoder().decode(jsonObject_vx.getString("x")));
		String vx_y = new String(Base64.getDecoder().decode(jsonObject_vx.getString("y")));
		ByteString byteString_vx_x = ByteString.copyFromUtf8(vx_x);
		ByteString byteString_vx_y = ByteString.copyFromUtf8(vx_y);


		// Crear el objeto PabcSerializer.ECP
		PabcSerializer.ECP vx_proto = PabcSerializer.ECP.newBuilder()
				.setX(byteString_vx_x)
				.setY(byteString_vx_y)
				.build();

		// VX
		JSONObject jsonObject_vx = new JSONObject(jsonWebKey.getVx());
		ECP vx_ecp = createECPFromXY(jsonObject_vx);
		Group1ElementBLS461 vx_group1 = new Group1ElementBLS461(vx_ecp);

		// VY_M
		JSONObject jsonObject_vy_m = new JSONObject(jsonWebKey.getVy_m());
		ECP vy_m_ecp = createECPFromXY(jsonObject_vy_m);
		Group1ElementBLS461 vy_m_group1 = new Group1ElementBLS461(vy_m_ecp);

		// VY_EPOCH
		JSONObject jsonObject_vy_epoch = new JSONObject(jsonWebKey.getVy_epoch());
		ECP vy_epoch_ecp = createECPFromXY(jsonObject_vy_epoch);
		Group1ElementBLS461 vy_epoch_group1 = new Group1ElementBLS461(vy_epoch_ecp);

		//VY
		JSONObject jsonObject_vy = new JSONObject(jsonWebKey.getVy());
		Map<String, Group1Element> vy = new HashMap<>();

		for (String key : jsonObject_vy.keySet()) {
			JSONObject innerObject = jsonObject_vy.getJSONObject(key);

			ECP vy_ecp = createECPFromXY(innerObject);
			Group1ElementBLS461 vy_group1 = new Group1ElementBLS461(vy_ecp);

			// Add the decoded map to the final map
			vy.put(key, vy_group1);
		}

		return new PSverfKey(vx_group1,vy_m_group1,vy, vy_epoch_group1);
	}
	*/
	public static PSverfKey JWK_to_Psms_PublicKey(JWK jsonWebKey) {
		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.PSMS.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());
		System.out.println("test: "+jsonWebKey.getVx());
		byte[] decode_bytes_vx = Base64.getDecoder().decode(jsonWebKey.getVx());
		ByteString byteString_vx = ByteString.copyFrom(decode_bytes_vx);
		PabcSerializer.Group1Element group1ElementProto = null;
		PabcSerializer.ECP ecp = PabcSerializer.ECP.newBuilder()
				.setX(byteString_vx).build();
		group1ElementProto = PabcSerializer.Group1Element.newBuilder().setX(ecp).build();

		Group1ElementBLS461 group1Element = new Group1ElementBLS461(group1ElementProto);
		System.out.println("vx: "+Base64.getEncoder().encodeToString(group1Element.toBytes()));


		byte[] decode_bytes_vy_m = Base64.getDecoder().decode(jsonWebKey.getVy_m());


		byte[] decode_bytes_vy_epoch = Base64.getDecoder().decode(jsonWebKey.getVy_epoch());



		return null;
	}


	/*
	 * Convenience methods
	 */

	public static byte[] JWK_to_RSAPublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.RSAPublicKey_to_bytes(JWK_to_RSAPublicKey(jwk));
	}

	public static byte[] JWK_to_secp256k1PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.secp256k1PublicKey_to_bytes(JWK_to_secp256k1PublicKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G1PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.Bls12381G1PublicKey_to_bytes(JWK_to_Bls12381G1PublicKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G2PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.Bls12381G2PublicKey_to_bytes(JWK_to_Bls12381G2PublicKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G1PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.Bls48581G1PublicKey_to_bytes(JWK_to_Bls48581G1PublicKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G2PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.Bls48581G2PublicKey_to_bytes(JWK_to_Bls48581G2PublicKey(jwk));
	}

	public static byte[] JWK_to_Ed25519PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.Ed25519PublicKey_to_bytes(JWK_to_Ed25519PublicKey(jwk));
	}

	public static byte[] JWK_to_X25519PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.X25519PublicKey_to_bytes(JWK_to_X25519PublicKey(jwk));
	}

	public static byte[] JWK_to_P_256PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.P_256PublicKey_to_bytes(JWK_to_P_256PublicKey(jwk));
	}

	public static byte[] JWK_to_P_384PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.P_384PublicKey_to_bytes(JWK_to_P_384PublicKey(jwk));
	}

	public static byte[] JWK_to_P_521PublicKeyBytes(JWK jwk) {
		return PublicKeyBytes.P_521PublicKey_to_bytes(JWK_to_P_521PublicKey(jwk));
	}
}
