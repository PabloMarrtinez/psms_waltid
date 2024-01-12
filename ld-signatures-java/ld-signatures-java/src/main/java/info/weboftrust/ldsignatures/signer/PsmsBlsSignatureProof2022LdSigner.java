package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignatureProof2022_PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import inf.um.multisign.MSprivateKey;
import inf.um.psmultisign.PSverfKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignature2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignatureProof2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;
import io.ipfs.multibase.Multibase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Map;

public class PsmsBlsSignatureProof2022LdSigner extends LdSigner<PsmsBlsSignatureProof2022SignatureSuite>{

    public static JsonLDObject getCredential() {
        return credential;
    }

    public static void setCredential(JsonLDObject credential) {
        PsmsBlsSignatureProof2022LdSigner.credential = credential;
    }

    private static JsonLDObject credential;

    public PsmsBlsSignatureProof2022LdSigner(ByteSigner signer, JsonLDObject credential) {
        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATUREPROOF2022, signer, new URDNA2015UmuCanonicalizer());
        setCredential(credential);
    }

    public PsmsBlsSignatureProof2022LdSigner(PSverfKey privateKey, String nonce, String zkpFields, JsonLDObject credential) {
        this(new PsmsBlsSignatureProof2022_PrivateKeySigner(privateKey, nonce, zkpFields, credential), credential);
    }

    public PsmsBlsSignatureProof2022LdSigner(String nonce, String zkpFields) {
        this((ByteSigner) null, null);
    }



    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {


        LdProof ldProof = LdProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .build();

        // build the JWS and sign
        URDNA2015UmuCanonicalizer can = new URDNA2015UmuCanonicalizer();

        try {
            byte[] canonicalizationResult = can.canonicalize(ldProof, getCredential());
            String content_included = PsmsBlsUmuUtil.processRdfData(new String(canonicalizationResult));
            byte[] bytes = signer.sign(content_included.getBytes(StandardCharsets.UTF_8), Curve.PSMSPROOF);

            String proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);
            ldProofBuilder.proofValue(proofValue);

        } catch (IOException | JsonLDException e) {
            throw new RuntimeException(e);
        }


    }




    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {
        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
