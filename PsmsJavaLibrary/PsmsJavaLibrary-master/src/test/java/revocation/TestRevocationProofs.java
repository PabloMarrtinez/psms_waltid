package revocation;

import inf.um.model.attributes.*;
import inf.um.model.*;
import inf.um.util.Pair;
import inf.um.model.mathutils.PedersenBase;
import inf.um.model.mathutils.PedersenCommitment;
import inf.um.multisign.*;
import inf.um.pairingBLS461.PairingBuilderBLS461;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.psmultisign.*;
import inf.um.revocation.RevocationPredicateToken;
import inf.um.revocation.RevocationProver;
import inf.um.revocation.RevocationVerifier;
import org.junit.Test;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static inf.um.revocation.RevocationPredicateVerificationResult.VALID;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class TestRevocationProofs {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();

	private static final String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";


    @Test
    public void testCorrectVerification() throws Exception{
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);

      	Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("RevocationHandle".toLowerCase(), new Attribute(5723));
        int expectedEpoch=1234320;
        long revocationEpoch = 1234321;

        //Create and credentialGenerator module for each server.

		
		Set<String> attrNames = userAttr.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet());
		PSms psScheme = new PSms();
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		MSpublicParam publicParams = psScheme.setup(1,auxArg, seed);
        
		//generate private key
		Pair<MSprivateKey,MSverfKey> keyPair = psScheme.kg();
		
		
    	AttributeDefinition revocationHandleAttrDef = new AttributeDefinitionInteger("RevocationHandle", "RevocationHandle", 0, 1000000);
    	LinkedList<AttributeDefinition> attrDefList = new LinkedList<>();
    	attrDefList.add(revocationHandleAttrDef);
    	
        Map<String, ZpElement> attributesZpValues=new HashMap<>();
        Map<String,Attribute> attributeValues=new HashMap<>();
        for(AttributeDefinition attrDef: attrDefList){
            Attribute attributeValue = userAttr.get(attrDef.getId().toLowerCase());
            if(attributeValue!=null && attrDef.checkValidValue(attributeValue)){
                attributeValues.put(attrDef.getId().toLowerCase(),attributeValue);
                attributesZpValues.put(attrDef.getId().toLowerCase(),builder.getZpElementFromAttribute(attributeValue,attrDef));
            }
            else{ //this branch is not necessary... PANIIIIIC
                attributesZpValues.put(attrDef.getId().toLowerCase(),builder.getZpElementZero());
            }
        }
        
        MSsignature signature= psScheme.sign(keyPair.getFirst(),new PSmessage(attributesZpValues,builder.getZpElementFromEpoch(revocationEpoch)));

        PSCredential revocationCredential = new PSCredential(revocationEpoch,attributeValues,signature);
		RevocationProver revProver = new RevocationProver(builder, attrDefList, (PSpublicParam) publicParams, seed);
        
		assertTrue(psScheme.verf(keyPair.getSecond(), new PSmessage(attributesZpValues,builder.getZpElementFromEpoch(revocationEpoch)), signature));
		PedersenBase base=new PedersenBase(((PSverfKey)keyPair.getSecond()).getVY().get(revocationHandleAttrDef.getId().toLowerCase()), ((PSverfKey)keyPair.getSecond()).getVX());
		String policyID = "policyID";
        Pair<RevocationPredicateToken, PedersenCommitment> result = revProver.generateRevocationPredicateToken(base,revocationHandleAttrDef, revocationCredential, keyPair.getSecond(), policyID);

        
        RevocationVerifier verifier=new RevocationVerifier(builder, attrDefList, (PSpublicParam) publicParams, seed);
        assertSame(VALID, verifier.verifyRevocationPredicate(base,revocationHandleAttrDef, result.getFirst(), keyPair.getSecond(), policyID, expectedEpoch));

    }
    


}