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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

import foundation.identity.jsonld.JsonLDObject;

public class PsmsBlsSignatureProof2022_PrivateKeySigner extends PrivateKeySigner<MSverfKey> {

    private String nonce;
    private String zkpfields;
    private  JsonLDObject credential;
    public PsmsBlsSignatureProof2022_PrivateKeySigner(MSverfKey privateKey, String n, String zkpf, JsonLDObject credential) {

        super(privateKey, Curve.PSMSPROOF);
        this.nonce = n;
        this.zkpfields = zkpf;
        this.credential = credential;
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {
        MSsignature signature = PsmsUmuUtils.getSignature(this.credential);

        String content_string = new String(content, StandardCharsets.UTF_8);

        Map<String, String> digest = PsmsUmuUtils.getDigest(content_string);
        Map<String, ZpElement> values = PsmsUmuUtils.zkp_Attributes(digest);
        int seedLength = PsmsUmuUtils.FIELD_BYTES;
        RAND rng = new RAND();
        rng.clean();
        byte[] raw=new byte[seedLength];
        rng.seed(seedLength,raw);
        ZpElement epoch=new ZpElementBLS461(new BIG(123456789));
        MS psScheme=new PSms();
        MSauxArg auxArg=new PSauxArg(PsmsUmuUtils.PAIRING_NAME,PsmsUmuUtils.getAttrNames(content_string));
        try {
            psScheme.setup(1, auxArg, PsmsUmuUtils.seed);
        } catch (MSSetupException e) {
            throw new RuntimeException(e);
        }
        MSmessage mAttr=new PSmessage(values,epoch);


        PSzkToken token=(PSzkToken) psScheme.presentZKtoken(this.getPrivateKey(),PsmsUmuUtils.extractFields(this.zkpfields),mAttr,this.nonce,signature);
        PabcSerializer.PSzkToken zkToken = token.toProto();


        return zkToken.toByteArray();
    }
}
