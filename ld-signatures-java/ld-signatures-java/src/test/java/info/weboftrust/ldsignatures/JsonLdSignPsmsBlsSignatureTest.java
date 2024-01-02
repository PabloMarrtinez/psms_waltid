package info.weboftrust.ldsignatures;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import inf.um.psmultisign.PSauxArg;
import inf.um.psmultisign.PSprivateKey;
import inf.um.psmultisign.PSverfKey;
import inf.um.util.Pair;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.PsmsBlsSignature2022Signer;

import info.weboftrust.ldsignatures.verifier.PsmsBlsSignature2022LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import inf.um.psmultisign.PSms;
import inf.um.multisign.*;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.pairingInterfaces.Group1Element;


public class JsonLdSignPsmsBlsSignatureTest {

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
        PsmsBlsSignature2022Signer signer = new PsmsBlsSignature2022Signer(keys.getFirst());
        PsmsBlsSignature2022LdVerifier verifier = new PsmsBlsSignature2022LdVerifier(keys.getSecond());
        PSprivateKey p = (PSprivateKey) keys.getFirst();
        System.out.println("x: "+p.getX().toProto().toString());
        System.out.println("y_m: "+p.getY_m().toProto().toString());
        System.out.println("epoch: "+p.getY_epoch().toProto().toString());

        for (Map.Entry<String, ZpElement> entrada : p.getY().entrySet()) {
            String clave = entrada.getKey();
            ZpElement valor = entrada.getValue();
            System.out.println("Clave: " + clave + ", Valor: " + valor);
        }


        PSverfKey k = (PSverfKey) keys.getSecond();
        System.out.println("vx: "+k.getVX().toProto().toString());
        System.out.println("vy_m: "+k.getVY_m().toProto().toString());
        System.out.println("vy_epoch: "+k.getVY_epoch().toProto().toString());


        for (Map.Entry<String, Group1Element> entrada : k.getVY().entrySet()) {
            String clave = entrada.getKey();
            Group1Element valor = entrada.getValue();
            System.out.println("Clave: " + clave + ", Valor: " + valor.toProto().toString());
        }

        LdProof ldProof = signer.sign(jsonLdObject);

        boolean verify = verifier.verify(jsonLdObject,ldProof);
        assertTrue(verify);


    }
}
