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

public class PsmsBlsSignatureProof2022LdVerifier extends LdVerifier<PsmsBlsSignatureProof2022SignatureSuite>{

    public PsmsBlsSignatureProof2022LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATUREPROOF2022, verifier, new URDNA2015UmuCanonicalizer());
    }

    public PsmsBlsSignatureProof2022LdVerifier(MSverfKey publicKey) {

        this(new PsmsBlsSignatureProof2022_PublicKeyVerifier(publicKey));
    }

    public PsmsBlsSignatureProof2022LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {
        String content = new String(signingInput);
        String content_excluded = PsmsBlsUmuUtil.processRdfData(content);

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
