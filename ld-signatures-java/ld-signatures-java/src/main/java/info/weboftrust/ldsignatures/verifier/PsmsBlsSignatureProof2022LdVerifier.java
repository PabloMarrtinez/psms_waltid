package info.weboftrust.ldsignatures.verifier;


import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PublicKeyVerifier;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignatureProof2022_PublicKeyVerifier;
import com.danubetech.keyformats.jose.Curve;
import inf.um.multisign.MSverfKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignatureProof2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;
import io.ipfs.multibase.Multibase;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

public class PsmsBlsSignatureProof2022LdVerifier extends LdVerifier<PsmsBlsSignatureProof2022SignatureSuite>{

    private static Map<String,String> zkpFields;
    public PsmsBlsSignatureProof2022LdVerifier(ByteVerifier verifier,Map<String,String> zkpfields) {

        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATUREPROOF2022, verifier, new URDNA2015UmuCanonicalizer());
        zkpFields = zkpfields;
    }

    public PsmsBlsSignatureProof2022LdVerifier(MSverfKey publicKey, String nonce, Map<String,String> zkpFields) {

        this(new PsmsBlsSignatureProof2022_PublicKeyVerifier(publicKey,nonce, zkpFields),zkpFields);
    }

    public static Map<String, String> getZkpFields() {
        return zkpFields;
    }

    public static void setZkpFields(Map<String, String> zkpFields) {
        PsmsBlsSignatureProof2022LdVerifier.zkpFields = zkpFields;
    }

    public PsmsBlsSignatureProof2022LdVerifier(Map<String,String> zkpfields) {

        this(null, zkpfields);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {
        String content = new String(signingInput);
        String content_excluded = PsmsBlsUmuUtil.zkp_fields(content,getZkpFields().keySet());
        String proofValue = ldProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");
        byte[] bytes = Multibase.decode(proofValue);
        return verifier.verify(content_excluded.getBytes(StandardCharsets.UTF_8), bytes, Curve.PSMS);
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }

}
