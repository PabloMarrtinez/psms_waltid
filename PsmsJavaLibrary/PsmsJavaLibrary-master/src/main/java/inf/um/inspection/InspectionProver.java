package inf.um.inspection;

import inf.um.model.attributes.*;
import inf.um.util.Pair;
import inf.um.inspection.model.*;
import inf.um.model.mathutils.PedersenBase;
import inf.um.model.mathutils.PedersenCommitment;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;

import static inf.um.inspection.tools.Utils.newChallenge;


/**
 * Exposes high level abstraction of Range Proofs to be used by the OL prover (credMngmnt). Idea is to create a new RangeProver for each presentation process,
 * which generates all the necessary range proofs (and uses the same salt for base generation, for example the policy ID).
 */
public class InspectionProver {
    private PedersenCommitment generatedCommitment;
    private PairingBuilder builder;

    public InspectionProver(PairingBuilder builder){
        this.builder=builder;
    }

    /**
     * Generates a token for an inspectable proof, i.e., generates a commitment and an encryption of the identity and a proof that they are correct.
     * @param base Pedersen base for the proof 
     * @param value The attribute value of the identity to be encrypted
     * @param attributeDefinition The corresponding attribute definition. It has to be "numerical" (Integer or Date)
     * @param inspectionPK public key of the inspection scheme to be used for encryption
     * @return
     */
    public Pair<InspectionPredicateToken,PedersenCommitment> generateInspectionPredicateToken(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, ElGamalKey inspectionPK){
    	//TODO: Any sanity checks to be performed?? May ID needs to be integer?
        //System.err.println("Inspection prover");
        ZpElement id    = builder.getZpElementFromAttribute(value,attributeDefinition);
    	ZpElement Rid   = builder.getRandomZpElement();

    	ZpElement open  = builder.getRandomZpElement();
    	ZpElement Ropen = builder.getRandomZpElement();

    	ZpElement rand  = builder.getRandomZpElement();
    	ZpElement Rrand = builder.getRandomZpElement();

    	
        PedersenCommitment V = new PedersenCommitment(base.getG(),base.getH(), id, open);     //V=X^id Y^open
    	ElGamalCiphertext  E = new ElGamalEncryption(inspectionPK, inspectionPK.getBase().exp(id), rand).getCiphertext(); //E encrypts base^id under randomness rand
    			
        PedersenCommitment t_V = new PedersenCommitment(base.getG(),base.getH(), Rid, Ropen);     
    	ElGamalCiphertext  t_E = new ElGamalEncryption(inspectionPK, inspectionPK.getBase().exp(Rid), Rrand).getCiphertext();  
 
    	//TODO: I guess we should also include the bases of the commitment and the public key here to avoid ambiguity? Makes sense, yes
		ZpElement c = newChallenge(V.getV(), E, t_V.getV(), t_E, builder);

    	// S_id = R_id + c*id
    	ZpElement Sid   = Rid.add(id.mul(c));
    	ZpElement Sopen = Ropen.add(open.mul(c));
    	ZpElement Srand = Rrand.add(rand.mul(c));


    	InspectionPredicateToken proofToken = new InspectionPredicateToken(Sid,Sopen,Srand,c,V.getV(),E);
    	
    	return new Pair<>(proofToken,V);
    }


    /**
     * After the proof has been executed with this Prover instance, you can retrieve the commitment for the attribute so you can use it as
     * needed (e.g., for linking proof...). 
     * @return
     */
    public PedersenCommitment getGeneratedCommitment() {
        return generatedCommitment;
    }
}
