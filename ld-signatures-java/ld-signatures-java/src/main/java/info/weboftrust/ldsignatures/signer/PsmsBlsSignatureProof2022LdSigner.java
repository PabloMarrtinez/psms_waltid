package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignatureProof2022_PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

public class PsmsBlsSignatureProof2022LdSigner extends LdSigner<PsmsBlsSignatureProof2022SignatureSuite>{


    public PsmsBlsSignatureProof2022LdSigner(ByteSigner signer) {
        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATUREPROOF2022, signer, new URDNA2015UmuCanonicalizer());

    }

    public PsmsBlsSignatureProof2022LdSigner(PSverfKey privateKey, String nonce, Map<String, String> zkpFields, JsonLDObject credential) {
        this(new PsmsBlsSignatureProof2022_PrivateKeySigner(privateKey, nonce, zkpFields, credential));
    }

    public PsmsBlsSignatureProof2022LdSigner(String nonce, Map<String, String> zkpFields) {
        this((ByteSigner) null);
    }



    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign
        String content = new String(signingInput);
        String content_included = PsmsBlsUmuUtil.processRdfData(content);
        byte[] bytes = signer.sign(content_included.getBytes(StandardCharsets.UTF_8), Curve.PSMSPROOF);

        String proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);
        // add JSON-LD context

        //ldProofBuilder.contexts(Arrays.asList(LDSecurityContexts.JSONLD_CONTXT_WEID_SUITES_PSMS_BLS, LDSecurityContexts.JSONLD_CONTXT_CITIZENSHIP_V1, LDSecurityContexts.JSONLD_CONTXT_CREDENTIALS_2018));

        // done

        ldProofBuilder.proofValue(proofValue);

    }




    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
