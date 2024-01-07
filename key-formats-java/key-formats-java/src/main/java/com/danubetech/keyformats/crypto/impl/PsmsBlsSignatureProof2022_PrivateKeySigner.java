package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.util.PsmsUmuUtils;
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
import java.util.Map;
import foundation.identity.jsonld.JsonLDObject;

public class PsmsBlsSignatureProof2022_PrivateKeySigner extends PrivateKeySigner<MSverfKey> {

    private String nonce;
    private Map<String,String> zkpfields;
    private  JsonLDObject credential;
    public PsmsBlsSignatureProof2022_PrivateKeySigner(MSverfKey privateKey, String n, Map<String,String> zkpf, JsonLDObject credential) {

        super(privateKey, Curve.PSMSPROOF);
        this.nonce = n;
        this.zkpfields = zkpf;
        this.credential = credential;
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {
        MSsignature signature = PsmsUmuUtils.getSignature(this.credential);
        String s = new String(content, StandardCharsets.UTF_8);
        Map<String, String> diggest = PsmsUmuUtils.getDiggest(s);
        Map<String, ZpElement> values = PsmsUmuUtils.zkp_Attributes(diggest);
        int seedLength = PsmsUmuUtils.FIELD_BYTES;
        RAND rng = new RAND();
        rng.clean();
        byte[] raw=new byte[seedLength];
        rng.seed(seedLength,raw);
        ZpElement epoch=new ZpElementBLS461(new BIG(123456789));
        MS psScheme=new PSms();
        MSauxArg auxArg=new PSauxArg(PsmsUmuUtils.PAIRING_NAME,PsmsUmuUtils.getAttrNames(s));
        try {
            psScheme.setup(1, auxArg, PsmsUmuUtils.seed);
        } catch (MSSetupException e) {
            throw new RuntimeException(e);
        }
        MSmessage mAttr=new PSmessage(values,epoch);
        PSzkToken token=(PSzkToken) psScheme.presentZKtoken(this.getPrivateKey(),zkpfields.keySet(),mAttr,this.nonce,signature);
        PabcSerializer.PSzkToken zkToken = token.toProto();
        System.out.println("Token: "+ zkToken);
        return zkToken.toByteArray();
    }
}
