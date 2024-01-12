package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.Curve;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import com.danubetech.keyformats.util.PsmsUmuUtils;
import inf.um.model.exceptions.MSSetupException;
import inf.um.multisign.MSmessage;
import inf.um.psmultisign.PSsignature;
import inf.um.multisign.*;
import inf.um.pairingBLS461.ZpElementBLS461;
import inf.um.psmultisign.*;
import inf.um.pairingInterfaces.*;
import org.miracl.core.RAND;
import java.util.Map;
import org.miracl.core.BLS12461.BIG;
import inf.um.protos.PabcSerializer;

public class PsmsBlsSignature2022_PrivateKeySigner extends PrivateKeySigner<MSprivateKey> {

    public PsmsBlsSignature2022_PrivateKeySigner(MSprivateKey privateKey) {
        super(privateKey, Curve.PSMS);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

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
        PSsignature signature = (PSsignature) psScheme.sign(this.getPrivateKey(),mAttr);

        PabcSerializer.PSsignature protoSignature = signature.toProto();

        return protoSignature.toByteArray();
    }
}
