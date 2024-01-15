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




    public static Map<String, String> getDigest(String input) {
        System.out.println(input);
        Map<String, String> attributeValues = new HashMap<>();
        String[] lines = input.split("\n");
        Pattern pattern = Pattern.compile("<[^>]+>\\s+<([^>]+)>\\s+(\\\"[^\\\"]+\\\"|<([^>]+)>)(?:\\^\\^<([^>]+)>)?\\s*\\.");
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String attribute = matcher.group(1);
                String value = matcher.group(2);
                attributeValues.put(attribute, value);
            }

        }
        return attributeValues;
    }

/*
    public static Map<String, String> getDigest(String input) {
        System.out.println(input);
        Map<String, String> attributeValues = new HashMap<>();
        String[] lines = input.split("\n");
        Pattern pattern = Pattern.compile("(<did:example:[^>]+>)\\s+<([^>]+)>\\s+(\\\"[^\\\"]+\\\"|<([^>]+)>)(?:\\^\\^<([^>]+)>)?\\s*\\.");
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String subject = matcher.group(1);
                String attribute = matcher.group(2);
                String value = matcher.group(3);
                System.out.println(attribute+" : "+value);
                if (subject.startsWith("<did:example:")) {
                    attributeValues.put(attribute, value);
                }
            }
        }
        return attributeValues;
    }
*/

    public static Map<String, ZpElement> zkp_Attributes(Map<String, String> input) {
        Map<String, ZpElement> attributeValues = new HashMap<>();
        for (Map.Entry<String, String> entry : input.entrySet()) {
            String attrDef = entry.getKey();
            String attrValue = entry.getValue();
            Attribute attr_value = new Attribute(attrValue);
            AttributeDefinition attr_def = new AttributeDefinitionString(attrDef,attrDef,1,10000);
            ZpElement zpElement = builder.getZpElementFromAttribute(attr_value, attr_def);
            System.out.println(attrDef);
            attributeValues.put(attrDef, zpElement);
        }
        return attributeValues;
    }



    public static Set<String> getAttrNames(String input) {
        Set<String> attrNames = new HashSet<>();
        String[] lines = input.split("\n");
        Pattern pattern = Pattern.compile("<[^>]+>\\s+<([^>]+)>\\s+(\\\"[^\\\"]+\\\"|<([^>]+)>)(?:\\^\\^<([^>]+)>)?\\s*\\.");
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String attribute = matcher.group(1);
                attrNames.add(attribute);
            }
        }
        return attrNames;
    }


/*
    public static Set<String> getAttrNames(String input) {
        Set<String> attrNames = new HashSet<>();
        String[] lines = input.split("\n");
        Pattern pattern = Pattern.compile("(<did:example:[^>]+>)\\s+<([^>]+)>\\s+(\\\"[^\\\"]+\\\"|<([^>]+)>)(?:\\^\\^<([^>]+)>)?\\s*\\.");
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String attribute = matcher.group(1);
                attrNames.add(attribute);
            }
        }
        return attrNames;
    }
*/

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

    public static Set<String> extractFields(String json) {
        Set<String> fields = new HashSet<>();
        ObjectMapper mapper = new ObjectMapper();

        try {
            JsonNode rootNode = mapper.readTree(json);
            JsonNode credentialSubjectNode = rootNode.path("credentialSubject");

            if (credentialSubjectNode.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> fieldsIterator = credentialSubjectNode.fields();
                while (fieldsIterator.hasNext()) {
                    Map.Entry<String, JsonNode> field = fieldsIterator.next();
                    if (!field.getKey().equals("@explicit")) { // Ignorando la clave @explicit
                        fields.add(field.getKey());
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return fields;
    }

}
