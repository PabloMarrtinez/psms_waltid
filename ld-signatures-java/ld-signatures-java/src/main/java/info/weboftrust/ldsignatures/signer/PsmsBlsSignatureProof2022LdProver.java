package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteProver;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignatureProof2022_PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import foundation.identity.jsonld.JsonLDObject;
import inf.um.psmultisign.PSverfKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignatureProof2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;
import io.ipfs.multibase.Multibase;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class PsmsBlsSignatureProof2022LdProver extends LdProver<PsmsBlsSignatureProof2022SignatureSuite>{

    public static JsonLDObject getCredential() {
        return credential;
    }

    public static void setCredential(JsonLDObject credential) {
        PsmsBlsSignatureProof2022LdProver.credential = credential;
    }

    private static JsonLDObject credential;

    public PsmsBlsSignatureProof2022LdProver(ByteProver signer, JsonLDObject credential) {
        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATUREPROOF2022, signer, new URDNA2015UmuCanonicalizer());
        setCredential(credential);
    }

    public PsmsBlsSignatureProof2022LdProver(PSverfKey privateKey, String nonce, JsonLDObject credential) {
        this(new PsmsBlsSignatureProof2022_PrivateKeySigner(privateKey, nonce, credential), credential);
    }

    public PsmsBlsSignatureProof2022LdProver(String nonce) {
        this((ByteProver) null, null);
    }



    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] credential,byte[] presentation, ByteProver signer) throws GeneralSecurityException {

            String content_included_credential = PsmsBlsUmuUtil.processRdfData(new String(credential));
            String content_included_presentation = PsmsBlsUmuUtil.processRdfData(new String(presentation));
            byte[] bytes = signer.sign(content_included_credential.getBytes(StandardCharsets.UTF_8),content_included_presentation.getBytes(StandardCharsets.UTF_8), Curve.PSMSPROOF);
            String proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);
            ldProofBuilder.proofValue(proofValue);

    }




    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] credential,byte[] presentation) throws GeneralSecurityException {
        sign(ldProofBuilder, credential, presentation, this.getSigner());
    }
}
