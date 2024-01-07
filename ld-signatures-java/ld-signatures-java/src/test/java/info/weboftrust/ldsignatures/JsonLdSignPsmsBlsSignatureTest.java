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

    private static final String zkp_fields = "{\"http://schema.org/familyName\":\"REVEAL\", \"http://schema.org/gender\":\"REVEAL\", \"http://schema.org/givenName\":\"REVEAL\", \"http://schema.org/image\":\"REVEAL\"}";

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
        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignPsmsBlsSignatureTest.class.getResourceAsStream("vc_umu.jsonld"))));
        jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

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
        PSprivateKey p = (PSprivateKey) keys.getFirst();
        System.out.println("PRIVATE KEY");
        System.out.println("x: "+Base64.getEncoder().encodeToString(p.getX().toBytes()));
        byte[] decodedBytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(p.getX().toProto().toByteArray()));
        ByteString byteString = ByteString.copyFrom(decodedBytes);
        PabcSerializer.ZpElement zpElementProto_ym = PabcSerializer.ZpElement.newBuilder()
                .setX(byteString)
                .build();

        System.out.println("y_m: "+Base64.getEncoder().encodeToString(p.getY_m().toBytes()));
        System.out.println("epoch: "+Base64.getEncoder().encodeToString(p.getY_epoch().toBytes()));

        for (Map.Entry<String, ZpElement> entrada : p.getY().entrySet()) {
            String clave = entrada.getKey();
            ZpElement valor = entrada.getValue();
            System.out.println("Clave: " + clave + ", Valor: " + Base64.getEncoder().encodeToString(valor.toBytes()));
        }

        System.out.println("PUBLIC KEY");

        PSverfKey k = (PSverfKey) keys.getSecond();
        System.out.println("vx: "+Base64.getEncoder().encodeToString(k.getVX().toBytes()));
        System.out.println("vy_m: "+Base64.getEncoder().encodeToString(k.getVY_m().toBytes()));
        System.out.println("vy_epoch: "+Base64.getEncoder().encodeToString(k.getVY_epoch().toBytes()));


        for (Map.Entry<String, Group1Element> entrada : k.getVY().entrySet()) {
            String clave = entrada.getKey();
            Group1Element valor = entrada.getValue();
            System.out.println("Clave: " + clave + ", Valor: " + Base64.getEncoder().encodeToString(valor.toBytes()));
        }

        LdProof ldProof = signer.sign(jsonLdObject);
        System.out.println("-----------------------------");
        boolean verify = verifier.verify(jsonLdObject,ldProof);
        assertTrue(verify);












        // CREDENTIAL /
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> zkpFields = objectMapper.readValue(zkp_fields, new TypeReference<Map<String, String>>() {});
        String nonce = "123456789";
        System.out.println("ldObject: "+ldProof);

        PsmsBlsSignatureProof2022LdSigner signerProof = new PsmsBlsSignatureProof2022LdSigner((PSverfKey) keys.getSecond(),nonce,zkpFields,ldProof);
        LdProof zkproof = signerProof.sign(jsonLdObject);





    }
}
