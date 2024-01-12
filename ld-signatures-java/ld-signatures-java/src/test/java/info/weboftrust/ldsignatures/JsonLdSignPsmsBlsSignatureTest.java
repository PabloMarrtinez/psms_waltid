package info.weboftrust.ldsignatures;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import foundation.identity.jsonld.JsonLDObject;
import inf.um.protos.PabcSerializer;
import inf.um.psmultisign.PSauxArg;
import inf.um.psmultisign.PSprivateKey;
import inf.um.psmultisign.PSverfKey;
import inf.um.util.Pair;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.PsmsBlsSignature2022LdSigner;

import info.weboftrust.ldsignatures.signer.PsmsBlsSignatureProof2022LdSigner;
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignature2022LdVerifier;
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignatureProof2022LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.*;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import inf.um.psmultisign.PSms;
import inf.um.multisign.*;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.pairingInterfaces.Group1Element;
import com.fasterxml.jackson.core.type.TypeReference;


public class JsonLdSignPsmsBlsSignatureTest {

    String zkp_fields_json = "{"
            + "\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://w3id.org/citizenship/v1\",\"https://ssiproject.inf.um.es/security/psms/v1\"], "
            + "\"credentialSubject\":{\"@explicit\":true, \"https://w3id.org/citizenship#birthCountry\":{},\"https://www.w3.org/2018/credentials#credentialSubject\":{},\"http://schema.org/familyName\":{}},"
            + "\"expirationDate\":{},"
            + "\"issuer\":{}, "
            + "\"type\":[\"VerifiableCredential\",\"PermanentResidentCard\"]"
            + "}";

    @BeforeEach
    public void before() {

        RandomProvider.set(new JavaRandomProvider());
        SHA256Provider.set(new JavaSHA256Provider());
        Ed25519Provider.set(new TinkEd25519Provider());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testSign() throws Throwable {

        // Leo el documento JSON
        JsonLDObject credential = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignPsmsBlsSignatureTest.class.getResourceAsStream("vc_umu.jsonld"))));
        credential.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

        MS psScheme=new PSms();

        Set<String> attrNames=new HashSet<>(Arrays.asList(
                "http://schema.org/birthDate",
                "http://schema.org/familyName",
                "http://schema.org/gender",
                "http://schema.org/givenName",
                "http://schema.org/image",
                "https://w3id.org/citizenship#birthCountry",
                "https://w3id.org/citizenship#commuterClassification",
                "https://w3id.org/citizenship#lprCategory",
                "https://w3id.org/citizenship#lprNumber",
                "https://w3id.org/citizenship#residentSince",
                "http://schema.org/description",
                "http://schema.org/name",
                "https://www.w3.org/2018/credentials#issuanceDate",
                "https://www.w3.org/2018/credentials#credentialSubject",
                "https://www.w3.org/2018/credentials#expirationDate",
                "https://www.w3.org/2018/credentials#issuer"));




        String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";

        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        psScheme.setup(1,auxArg, "seed".getBytes());


        Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
        PsmsBlsSignature2022LdSigner signer = new PsmsBlsSignature2022LdSigner(keys.getFirst());
        PsmsBlsSignature2022LdVerifier verifier = new PsmsBlsSignature2022LdVerifier(keys.getSecond());


        LdProof ldProof = signer.sign(credential);
        boolean verify = verifier.verify(credential,ldProof);
        assertTrue(verify);

        // CREDENTIAL /

        JsonLDObject presentation = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignPsmsBlsSignatureTest.class.getResourceAsStream("vc_presentation_zkp.jsonld"))));
        presentation.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);
        String nonce = "123456789";


        PsmsBlsSignatureProof2022LdSigner signerProof = new PsmsBlsSignatureProof2022LdSigner((PSverfKey) keys.getSecond(),nonce,zkp_fields_json, credential);
        PsmsBlsSignatureProof2022LdVerifier verifierProof = new PsmsBlsSignatureProof2022LdVerifier(keys.getSecond(), nonce, zkp_fields_json);

        LdProof zkproof = signerProof.sign(presentation);
        boolean verifyProof = verifierProof.verify(presentation,zkproof);
        assertTrue(verifyProof);













    }
}
