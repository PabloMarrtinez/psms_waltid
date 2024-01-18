package com.danubetech.keyformats.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.InvalidProtocolBufferException;
import foundation.identity.jsonld.JsonLDObject;
import inf.um.model.attributes.Attribute;
import inf.um.model.attributes.AttributeDefinition;
import inf.um.model.attributes.AttributeDefinitionString;
import inf.um.multisign.MSsignature;
import inf.um.pairingBLS461.PairingBuilderBLS461;
import inf.um.pairingInterfaces.PairingBuilder;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.protos.PabcSerializer;
import inf.um.psmultisign.PSsignature;
import inf.um.util.Pair;
import org.miracl.core.BLS12461.CONFIG_BIG;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.ipfs.multibase.Multibase;

public class PsmsUmuUtils {

    public static final PairingBuilder builder = new PairingBuilderBLS461();
    public static final String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";
    public static final byte[] seed = "random value random value random value random value random".getBytes();

    public static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;




    public static  Map<String, String> getDigest(String doc) {
        Pattern subjectRegex = Pattern.compile("<https://www.w3.org/2018/credentials#credentialSubject>\\s+<?([^<>\\t\\n\\f\\r ]+)>?\\s+\\.");
        Matcher matcher = subjectRegex.matcher(doc);

        List<String> ids = new ArrayList<>();
        while (matcher.find()) {
            String id = matcher.group(1);
            if (!id.isEmpty()) {
                ids.add(id);
            }
        }
        Map<String, String> attributeValues = new HashMap<>();
        for (String id : ids) {
            Pattern attrRegex = Pattern.compile("<?" + Pattern.quote(id) + ">?\\s+<([^>]+)>\\s+(.+)\\s+\\.\n");
            Matcher attrMatcher = attrRegex.matcher(doc);
            while (attrMatcher.find()) {
                String attrName = attrMatcher.group(1);
                String attrValue = attrMatcher.group(2);
                if (isIdentifier(attrValue)) {
                    String recursedValues = parseJsonAttribute(doc, attrValue);
                    attributeValues.put(attrName, attrValue + " " + recursedValues);
                } else {
                    attributeValues.put(attrName, attrValue);
                }
            }
        }

        return attributeValues;
    }

    public static boolean isIdentifier(String att) {
        Pattern pattern = Pattern.compile("(^_:\\S+$)|<(urn:bnid:_:\\S+?>$)"); // \\S == [^\t\n\f\r ]
        Matcher matcher = pattern.matcher(att);
        return matcher.matches();
    }


    public static String parseJsonAttribute(String doc, String identifier) {
        StringBuilder result = new StringBuilder();
        Pattern attrRegex = Pattern.compile("<?" + Pattern.quote(identifier) + ">?\\s+<([^>]+)>\\s+(.+)\\s+\\.\n");
        // REGEX 2 : <did:example:[^>]+>\\s+<([^>]+)>\\s+(\\\"[^\\\"]+\\\"|<([^>]+)>)(?:\\^\\^<([^>]+)>)?\\s*\\.
        Matcher matcher = attrRegex.matcher(doc);

        while (matcher.find()) {
            String attr1 = matcher.group(1);
            String attr2 = matcher.group(2);
            if (isIdentifier(attr1)) {
                String recursedValues = parseJsonAttribute(doc, attr1);
                result.append(recursedValues).append(".");
            } else {
                result.append(attr1).append(" ").append(attr2).append(".");
            }
        }
        return result.toString();
    }


    public static Map<String, ZpElement> zkp_Attributes(Map<String, String> input) {
        Map<String, ZpElement> attributeValues = new HashMap<>();
        for (Map.Entry<String, String> entry : input.entrySet()) {
            String attrDef = entry.getKey();
            String attrValue = entry.getValue();
            Attribute attr_value = new Attribute(attrValue);
            AttributeDefinition attr_def = new AttributeDefinitionString(attrDef,attrDef,1,10000);
            ZpElement zpElement = builder.getZpElementFromAttribute(attr_value, attr_def);
            attributeValues.put(attrDef, zpElement);
        }
        return attributeValues;
    }


    public static PSsignature getSignature(JsonLDObject credential) {
        String json = credential.toString(); // Reemplaza esto con tu método para obtener el JSON como String
        ObjectMapper mapper = new ObjectMapper();

        try {
            Map<String, Object> jsonMap = mapper.readValue(json, Map.class);

            Map<String, Object> proofMap = (Map<String, Object>) jsonMap.get("proof");
            if (proofMap == null) {
                throw new RuntimeException("Proof field not found in the credential");
            }

            String proofValue = (String) proofMap.get("proofValue");
            if (proofValue == null) {
                throw new RuntimeException("ProofValue field not found in the proof");
            }

            byte[] decodedBytes = Multibase.decode(proofValue);
            PabcSerializer.PSsignature protoSignature = PabcSerializer.PSsignature.parseFrom(decodedBytes);
            return new PSsignature(protoSignature);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error processing JSON", e);
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException("Error processing protocol buffer", e);
        }
    }




}
