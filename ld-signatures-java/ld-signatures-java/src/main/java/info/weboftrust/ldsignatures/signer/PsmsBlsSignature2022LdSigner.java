package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import inf.um.multisign.MSprivateKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignature2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;

public class PsmsBlsSignature2022LdSigner extends LdSigner<PsmsBlsSignature2022SignatureSuite> {



    public PsmsBlsSignature2022LdSigner(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATURE2022, signer, new URDNA2015UmuCanonicalizer());
    }

    public PsmsBlsSignature2022LdSigner(MSprivateKey privateKey) {

        this(new PsmsBlsSignature2022_PrivateKeySigner(privateKey));
    }

    public PsmsBlsSignature2022LdSigner() {

        this((ByteSigner) null);
    }

    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        String content = new String(signingInput);
        String content_excluded = PsmsBlsUmuUtil.processRdfData(content);
        byte[] bytes = signer.sign(content_excluded.getBytes(StandardCharsets.UTF_8), Curve.PSMS);
        String proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);
        ldProofBuilder.proofValue(proofValue);

    }




    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {
        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
