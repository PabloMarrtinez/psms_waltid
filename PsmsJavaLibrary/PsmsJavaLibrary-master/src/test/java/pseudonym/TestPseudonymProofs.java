package pseudonym;

import inf.um.model.attributes.*;
import inf.um.util.Pair;
import inf.um.model.mathutils.PedersenBase;
import inf.um.model.mathutils.PedersenCommitment;
import inf.um.pairingBLS461.PairingBuilderBLS461;
import inf.um.pairingInterfaces.Group1Element;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pseudonym.PseudonymPredicateToken;
import inf.um.pseudonym.PseudonymProver;
import inf.um.pseudonym.PseudonymVerifier;
import org.junit.Test;

import static inf.um.pseudonym.PseudonymPredicateVerificationResult.INVALID;
import static inf.um.pseudonym.PseudonymPredicateVerificationResult.VALID;
import static org.junit.Assert.assertSame;

public class TestPseudonymProofs {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static AttributeDefinition definitionInspectionAttribute=new AttributeDefinitionInteger("id","id",0,1000000);



    @Test
    public void testCorrectVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        String scope = "cs4eu:pseudonym:test";
        PseudonymProver prover=new PseudonymProver(builder);
        PedersenBase base=generateTestPedersenBase(builder);
        Attribute id=new Attribute(10312);
        Pair<PseudonymPredicateToken, PedersenCommitment> result=prover.generatePseudonymPredicateToken(base,id,definitionInspectionAttribute,scope);
        PseudonymVerifier verifier=new PseudonymVerifier(builder);
        assertSame(VALID, verifier.verifyPseudonymPredicate(base, result.getFirst(), scope));
    }



    @Test
    public void testFalseVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        String scope = "cs4eu:pseudonym:test";
        String anotherScope = "cs4eu:pseudonym:test2";
        PseudonymProver prover=new PseudonymProver(builder);
        PedersenBase base=generateTestPedersenBase(builder);
        Attribute id=new Attribute(10312);
        Attribute anotherId=new Attribute(20312);
        Pair<PseudonymPredicateToken, PedersenCommitment> result=prover.generatePseudonymPredicateToken(base,id,definitionInspectionAttribute,scope);
        Pair<PseudonymPredicateToken, PedersenCommitment> result2=prover.generatePseudonymPredicateToken(base,anotherId,definitionInspectionAttribute,anotherScope);
        PseudonymPredicateToken token=result.getFirst();
        PseudonymPredicateToken token2=result2.getFirst();
        PseudonymPredicateToken modifiedToken=new PseudonymPredicateToken(token2.getV(),token.getP(),token.getS_id(),token.getS_open(),token.getC());
        PseudonymPredicateToken modifiedToken2=new PseudonymPredicateToken(token.getV(),token2.getP(),token.getS_id(),token.getS_open(),token.getC());
        PseudonymVerifier verifier=new PseudonymVerifier(builder);
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, token, anotherScope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken, scope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken2, scope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken, anotherScope));
        assertSame(INVALID, verifier.verifyPseudonymPredicate(base, modifiedToken2, anotherScope));
    }


    private PedersenBase generateTestPedersenBase(PairingBuilder builder) {
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element h=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new PedersenBase(g,h);
    }

}
