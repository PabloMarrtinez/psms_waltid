package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.PsmsBlsSignature2022_PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import inf.um.multisign.MSprivateKey;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015UmuCanonicalizer;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.suites.PsmsBlsSignature2022SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.ipfs.multibase.Multibase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.GeneralSecurityException;
import java.util.Collections;
import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil;

public class PsmsBlsSignature2022Signer extends LdSigner<PsmsBlsSignature2022SignatureSuite> {



    public PsmsBlsSignature2022Signer(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_PSMSBLSSIGNATURE2022, signer, new URDNA2015UmuCanonicalizer());
    }

    public PsmsBlsSignature2022Signer(MSprivateKey privateKey) {

        this(new PsmsBlsSignature2022_PrivateKeySigner(privateKey));
    }

    public PsmsBlsSignature2022Signer() {

        this((ByteSigner) null);
    }

    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign
        String content = new String(signingInput);
        String content_excluded = PsmsBlsUmuUtil.processRdfData(content);


        byte[] bytes = signer.sign(content_excluded.getBytes(StandardCharsets.UTF_8), Curve.PSMS);

        String proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);
        // add JSON-LD context

        ldProofBuilder.contexts(Arrays.asList(LDSecurityContexts.JSONLD_CONTXT_WEID_SUITES_PSMS_BLS, LDSecurityContexts.JSONLD_CONTXT_CITIZENSHIP_V1, LDSecurityContexts.JSONLD_CONTXT_CREDENTIALS_2018));

        // done

        ldProofBuilder.proofValue(proofValue);

    }




    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
