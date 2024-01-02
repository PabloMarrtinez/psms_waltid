package info.weboftrust.ldsignatures.canonicalizer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class URDNA2015UmuCanonicalizer extends Canonicalizer{


    public URDNA2015UmuCanonicalizer() {

        super(List.of("canonicalizersUmu"));
    }



    @Override
    public byte[] canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {
        LdProof ldProofWithoutProofValues = LdProof.builder()
                .base(ldProof)
                .defaultContexts(false)
                .build();

        LdProof.removeLdProofValues(ldProofWithoutProofValues);

        JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        String canonicalizedLdProofWithoutProofValues = ldProofWithoutProofValues.normalize("urdna2015");
        String canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize("urdna2015");

        String result = canonicalizedLdProofWithoutProofValues+canonicalizedJsonLdObjectWithoutProof;
        return result.getBytes(StandardCharsets.UTF_8);
    }

}
