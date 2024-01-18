package info.weboftrust.ldsignatures;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import foundation.identity.jsonld.JsonLDObject;
import inf.um.psmultisign.PSauxArg;
import inf.um.psmultisign.PSverfKey;
import inf.um.util.Pair;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.PsmsBlsSignature2022LdSigner;
import info.weboftrust.ldsignatures.signer.PsmsBlsSignatureProof2022LdProver;
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignature2022LdVerifier;
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignatureProof2022LdVerifier;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertTrue;
import inf.um.psmultisign.PSms;
import inf.um.multisign.*;



public class JsonLdSignPsmsBlsSignatureTest {

    Set<String> attrNames_1 =new HashSet<>(Arrays.asList(
            "http://schema.org/birthDate",
            "http://schema.org/familyName",
            "http://schema.org/gender",
            "http://schema.org/givenName",
            "http://schema.org/image",
            "https://w3id.org/citizenship#birthCountry",
            "https://w3id.org/citizenship#commuterClassification",
            "https://w3id.org/citizenship#lprCategory",
            "https://w3id.org/citizenship#lprNumber",
            "https://w3id.org/citizenship#residentSince"
    ));

    Set<String> attrNames_2 =new HashSet<>(Arrays.asList(
            "https://www.w3.org/ns/credentials/examples#alumniOf"
    ));

    String[] vc = {"vc_umu1.jsonld","vc_umu2.jsonld"};
    String[] frames = {"frame_umu1.jsonld","frame_umu2.jsonld"};

    @Test
    @SuppressWarnings("unchecked")
    public void testSign() throws Throwable {
        Set<String>[] attributes = new HashSet[2];
        attributes[0] = new HashSet<>();
        attributes[1] = new HashSet<>();
        attributes[0].addAll(attrNames_1);
        attributes[1].addAll(attrNames_2);

        for (int i = 0; i < vc.length; i++) {
            String credential_name = vc[i];
            String frame_name = frames[i];
            Set<String> attrNames_credential_subject = attributes[i];

        }









        // Leo el documento JSON
        JsonLDObject credential = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignPsmsBlsSignatureTest.class.getResourceAsStream("vc_umu1.jsonld"))));
        String frameString = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignPsmsBlsSignatureTest.class.getResourceAsStream("frame_umu1.jsonld")))).toString();
        credential.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

        // SETUP
        MS psScheme=new PSms();
        String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames_1);
        psScheme.setup(1,auxArg, "seed".getBytes());

        // K+ y K-
        Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();

        // CREDENTIAL ISSUER AND VERIFIER
        PsmsBlsSignature2022LdSigner signer = new PsmsBlsSignature2022LdSigner(keys.getFirst());
        LdProof ldProof = signer.sign(credential);

        System.out.println("CREDENTIAL");
        System.out.println(credential);

        PsmsBlsSignature2022LdVerifier verifier = new PsmsBlsSignature2022LdVerifier(keys.getSecond());
        boolean verify = verifier.verify(credential,ldProof);
        assertTrue(verify);

        JsonLdOptions options = new JsonLdOptions();
        options.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);
        Document vcDocument = JsonDocument.of(new ByteArrayInputStream(credential.toString().getBytes(StandardCharsets.UTF_8)));
        Document frameDocument = JsonDocument.of(new ByteArrayInputStream(frameString.getBytes(StandardCharsets.UTF_8)));
        JsonObject framedVcJson = JsonLd.frame(vcDocument, frameDocument).options(options).get();
        JsonLDObject presentation = JsonLDObject.fromJson(framedVcJson.toString());
        presentation.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

        String nonce = "123456789";

        System.out.println("FRAME");
        System.out.println(frameString);

        PsmsBlsSignatureProof2022LdProver signerProof = new PsmsBlsSignatureProof2022LdProver((PSverfKey) keys.getSecond(),nonce, credential);
        LdProof zkproof = signerProof.sign(credential,presentation);

        System.out.println("PRESENTATION");
        System.out.println(presentation);

        PsmsBlsSignatureProof2022LdVerifier verifierProof = new PsmsBlsSignatureProof2022LdVerifier(keys.getSecond(),
                );
        boolean verifyProof = verifierProof.verify(presentation,zkproof);

        assertTrue(verifyProof);
    }


}
