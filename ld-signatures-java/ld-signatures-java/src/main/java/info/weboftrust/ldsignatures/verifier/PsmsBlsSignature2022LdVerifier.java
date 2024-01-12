package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PublicKeyVerifier;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.util.PsmsUmuUtils;
import com.google.protobuf.InvalidProtocolBufferException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import inf.um.multisign.MSverfKey;
import inf.um.protos.PabcSerializer;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignature2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.ipfs.multibase.Multibase;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.ParseException;

import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;

public class PsmsBlsSignature2022LdVerifier extends LdVerifier<PsmsBlsSignature2022SignatureSuite> {


    public PsmsBlsSignature2022LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATURE2022, verifier, new URDNA2015UmuCanonicalizer());
    }

    public PsmsBlsSignature2022LdVerifier(MSverfKey publicKey) {

        this(new PsmsBlsSignature2022_PublicKeyVerifier(publicKey));
    }

    public PsmsBlsSignature2022LdVerifier() {

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
