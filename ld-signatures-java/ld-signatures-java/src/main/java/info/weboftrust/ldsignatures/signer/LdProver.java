package info.weboftrust.ldsignatures.signer;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.keyformats.crypto.ByteProver;
import com.danubetech.keyformats.crypto.ByteSigner;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;

public abstract  class LdProver <SIGNATURESUITE extends SignatureSuite>{

    private final SIGNATURESUITE signatureSuite;

    private ByteProver signer;
    private Canonicalizer canonicalizer;

    private URI creator;
    private Date created;
    private String domain;
    private String challenge;
    private String nonce;
    private String proofPurpose;
    private URI verificationMethod;

    protected LdProver(SIGNATURESUITE signatureSuite, ByteProver signer, Canonicalizer canonicalizer) {

        this.signatureSuite = signatureSuite;
        this.signer = signer;
        this.canonicalizer = canonicalizer;
    }

    protected LdProver(SIGNATURESUITE signatureSuite, ByteProver signer, Canonicalizer canonicalizer, URI creator, Date created, String domain, String challenge, String nonce, String proofPurpose, URI verificationMethod) {

        this.signatureSuite = signatureSuite;
        this.signer = signer;
        this.canonicalizer = canonicalizer;
        this.creator = creator;
        this.created = created;
        this.domain = domain;
        this.challenge = challenge;
        this.nonce = nonce;
        this.proofPurpose = proofPurpose;
        this.verificationMethod = verificationMethod;
    }

    /**
     * @deprecated
     * Use LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuiteTerm) instead.
     */
    @Deprecated
    public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(String signatureSuiteTerm) {
        return LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuiteTerm);
    }

    /**
     * @deprecated
     * Use LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite) instead.
     */
    @Deprecated
    public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(SignatureSuite signatureSuite) {
        return LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite);
    }

    public abstract void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, byte[] signingInput2) throws GeneralSecurityException;

    public LdProof sign(JsonLDObject credencial,JsonLDObject presentacion, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException {

        // build the base proof object

        LdProof ldProof = LdProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .type(this.getSignatureSuite().getTerm())
                .creator(this.getCreator())
                .created(this.getCreated())
                .domain(this.getDomain())
                .challenge(this.getChallenge())
                .nonce(this.getNonce())
                .proofPurpose(this.getProofPurpose())
                .verificationMethod(this.getVerificationMethod())
                .build();

        byte[] canonicalizationResult_credential = this.getCanonicalizer().canonicalize(ldProof, credencial);
        byte[] canonicalizationResult_presentation = this.getCanonicalizer().canonicalize(ldProof, presentacion);

        LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder = LdProof.builder()
                .base(ldProof)
                .defaultContexts(defaultContexts);
        this.sign(ldProofBuilder, canonicalizationResult_credential,canonicalizationResult_presentation);

        ldProof = ldProofBuilder.build();
        // add proof to JSON-LD

        if (addToJsonLdObject) ldProof.addToJsonLDObject(presentacion);
        loadMissingContext(presentacion);
        // done



        return ldProof;
    }

    private void loadMissingContext(JsonLDObject jsonLDObject){
        if(this.getSignatureSuite().getSupportedJsonLDContexts().stream().noneMatch(jsonLDObject.getContexts()::contains)){
            URI missingJsonLDContext = this.signatureSuite.getDefaultSupportedJsonLDContext();
            if (missingJsonLDContext != null) {
                JsonLDUtils.jsonLdAddAsJsonArray(jsonLDObject, Keywords.CONTEXT, missingJsonLDContext);
            }
        }
    }

    public LdProof sign(JsonLDObject credencial,JsonLDObject presentacion) throws IOException, GeneralSecurityException, JsonLDException {
        return this.sign(credencial,presentacion, true, false);
    }

    public SignatureSuite getSignatureSuite() {
        return this.signatureSuite;
    }

    /*
     * Getters and setters
     */

    public ByteProver getSigner() {
        return this.signer;
    }

    public void setSigner(ByteProver signer) {
        this.signer = signer;
    }

    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    public void setCanonicalizer(Canonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }

    public URI getCreator() {
        return creator;
    }

    public void setCreator(URI creator) {
        this.creator = creator;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public void setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
    }

    public URI getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(URI verificationMethod) {
        this.verificationMethod = verificationMethod;
    }
}
