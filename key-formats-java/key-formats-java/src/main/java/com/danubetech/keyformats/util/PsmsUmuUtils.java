package com.danubetech.keyformats.util;

import com.fasterxml.jackson.core.JsonProcessingException;
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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.ipfs.multibase.Multibase;

public class PsmsUmuUtils {

    public static final PairingBuilder builder = new PairingBuilderBLS461();
    public static final String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";
    public static final byte[] seed = "random value random value random value random value random".getBytes();

    public static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;




    public static Map<String, String> getDiggest(String input) {
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

    public static MSsignature getSignature(JsonLDObject credential) {
        String json = credential.toString(); // Reemplaza esto con tu método para obtener el JSON como String
        ObjectMapper mapper = new ObjectMapper();

        Map<String, Object> map = null;
        Map<String, Object> jsonMap = null;
        try {
            jsonMap = mapper.readValue(json, Map.class);
            String proofValue = (String) jsonMap.get("proofValue");
            byte[] decodedBytes = Multibase.decode(proofValue);
            PabcSerializer.PSsignature protoSignature = PabcSerializer.PSsignature.parseFrom(decodedBytes);
            return new PSsignature(protoSignature);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }

    }
}
