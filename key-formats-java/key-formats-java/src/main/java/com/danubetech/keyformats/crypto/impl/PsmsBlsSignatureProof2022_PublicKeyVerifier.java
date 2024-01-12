package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.util.PsmsUmuUtils;
import com.google.protobuf.InvalidProtocolBufferException;
import inf.um.model.exceptions.MSSetupException;
import inf.um.multisign.*;
import inf.um.pairingBLS461.ZpElementBLS461;
import inf.um.pairingInterfaces.ZpElement;
import inf.um.protos.PabcSerializer;
import inf.um.psmultisign.*;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.RAND;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;

public class PsmsBlsSignatureProof2022_PublicKeyVerifier extends PublicKeyVerifier<MSverfKey> {

    private String nonce;
    private String zkpfields;

    public PsmsBlsSignatureProof2022_PublicKeyVerifier(MSverfKey publicKey,String n, String zkpf) {

        super(publicKey, Curve.PSMS);
        this.nonce = n;
        this.zkpfields = zkpf;
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {
        try {
            PabcSerializer.PSzkToken zktoken = PabcSerializer.PSzkToken.parseFrom(signature);
            PSzkToken token = new PSzkToken(zktoken);
            Map<String, String> digest = PsmsUmuUtils.getDigest(new String(content, StandardCharsets.UTF_8));

            Map<String, ZpElement> values = PsmsUmuUtils.zkp_Attributes(digest);
            String test =  "http://schema.org/familyName,https://www.w3.org/2018/credentials#credentialSubject,https://w3id.org/citizenship#birthCountry";
            Set<String> hashSet = new HashSet<>(Arrays.asList(test.split(",")));


            Map<String, ZpElement> filteredMap = new HashMap<>();

            for (String key : values.keySet()) {
                if (hashSet.contains(key)) {
                    filteredMap.put(key, values.get(key));
                }
            }


            int seedLength = PsmsUmuUtils.FIELD_BYTES;
            RAND rng = new RAND();
            rng.clean();
            byte[] raw=new byte[seedLength];
            rng.seed(seedLength,raw);
            ZpElement epoch=new ZpElementBLS461(new BIG(123456789));
            MS psScheme=new PSms();

            Set<String> combinedKeySet = new HashSet<>();
            combinedKeySet.addAll(token.getVaj().keySet());
            combinedKeySet.addAll(values.keySet());


            MSauxArg auxArg=new PSauxArg(PsmsUmuUtils.PAIRING_NAME,combinedKeySet);
            try {
                psScheme.setup(1, auxArg, PsmsUmuUtils.seed);
            } catch (MSSetupException e) {
                throw new RuntimeException(e);
            }

            MSmessage mAttr=new PSmessage(filteredMap,epoch);
            return psScheme.verifyZKtoken(token,this.getPublicKey(),this.nonce, mAttr);

        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return false;
    }
}