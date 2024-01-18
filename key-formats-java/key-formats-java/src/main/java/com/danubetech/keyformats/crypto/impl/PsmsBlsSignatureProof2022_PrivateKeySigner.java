package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PublicKeyProver;
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

public class PsmsBlsSignatureProof2022_PrivateKeySigner extends PublicKeyProver<MSverfKey> {

    private String nonce;
    private Set<String> zkp_fields;
    private  JsonLDObject credential;
    public PsmsBlsSignatureProof2022_PrivateKeySigner(MSverfKey privateKey, String n, JsonLDObject credential) {

        super(privateKey, Curve.PSMSPROOF);
        this.nonce = n;
        this.credential = credential;
        this.zkp_fields = null;
    }

    public Set<String> getZkp_fields() {
        return zkp_fields;
    }

    public void setZkp_fields(Set<String> zkp_fields) {
        this.zkp_fields = zkp_fields;
    }


    @Override
    public byte[] sign(byte[] credential,byte[] presentation) throws GeneralSecurityException {
        String content_string_zkpfields = new String(presentation, StandardCharsets.UTF_8);
        Map<String, String> zkpfields = PsmsUmuUtils.getDigest(content_string_zkpfields);
        setZkp_fields(zkpfields.keySet());
        MSsignature signature = PsmsUmuUtils.getSignature(this.credential);

        String content_string = new String(credential, StandardCharsets.UTF_8);

        Map<String, String> digest = PsmsUmuUtils.getDigest(content_string);
        Map<String, ZpElement> values = PsmsUmuUtils.zkp_Attributes(digest);
        int seedLength = PsmsUmuUtils.FIELD_BYTES;
        RAND rng = new RAND();
        rng.clean();
        byte[] raw=new byte[seedLength];
        rng.seed(seedLength,raw);
        ZpElement epoch=new ZpElementBLS461(new BIG(123456789));
        MS psScheme=new PSms();
        MSauxArg auxArg=new PSauxArg(PsmsUmuUtils.PAIRING_NAME,digest.keySet());
        try {
            psScheme.setup(1, auxArg, PsmsUmuUtils.seed);
        } catch (MSSetupException e) {
            throw new RuntimeException(e);
        }
        MSmessage mAttr=new PSmessage(values,epoch);
        PSzkToken token=(PSzkToken) psScheme.presentZKtoken(this.getPrivateKey(),getZkp_fields(),mAttr,this.nonce,signature);
        PabcSerializer.PSzkToken zkToken = token.toProto();


        return zkToken.toByteArray();
    }


}
