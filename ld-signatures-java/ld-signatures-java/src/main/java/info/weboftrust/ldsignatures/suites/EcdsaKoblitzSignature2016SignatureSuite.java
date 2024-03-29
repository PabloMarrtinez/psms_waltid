package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class EcdsaKoblitzSignature2016SignatureSuite extends SignatureSuite {

	EcdsaKoblitzSignature2016SignatureSuite() {

		super(
				"EcdsaKoblitzSignature2016",
				URI.create("https://w3id.org/security#EcdsaKoblitzSignature2016"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#koblitz"),
				List.of(KeyTypeName.secp256k1),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				Arrays.asList(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
