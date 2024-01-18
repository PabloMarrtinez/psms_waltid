package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PsmsBlsSignature2022SignatureSuite extends SignatureSuite{

    PsmsBlsSignature2022SignatureSuite() {

        super(
                // TERM -> suite identifier
                "PsmsBlsSignature2022",
                // ID -> URI identifier
                URI.create("https://w3id.org/security#Ed25519Signature2018"),
                // canonicalizationAlgorithm -> URI that identify the canonicalization algorithm
                URI.create("https://w3id.org/security#URDNA2015"),
                // digestAlgorithm -> URI that identify the hash alhorithm
                URI.create("https://w3id.org/digests#sha256"),
                // proofAlgorithm -> URI that identify the algorithm to sign and verify
                URI.create("https://w3id.org/security#ed25519"),
                // keyTypeNames -> List of KeyTypeNames, which are identifiers of the key types supported by the signing suite.
                List.of(KeyTypeName.PsmsBlsSignature2022),
                // jwsAlgorithmForKeyTypeName -> Map that link each keytype to a list of JWS algorithmes
                Map.of(KeyTypeName.PsmsBlsSignature2022, List.of(JWSAlgorithm.PSMSAlg)),
                // supportedJsonLDContexts -> List of JSON-LD context that the suite allow
                Arrays.asList(LDSecurityContexts.JSONLD_CONTXT_WEID_SUITES_PSMS_BLS, LDSecurityContexts.JSONLD_CONTXT_CITIZENSHIP_V1));

    }
}
