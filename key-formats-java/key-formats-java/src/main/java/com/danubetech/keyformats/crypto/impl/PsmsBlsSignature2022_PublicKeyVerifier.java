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
import inf.um.psmultisign.PSauxArg;
import inf.um.psmultisign.PSmessage;
import inf.um.psmultisign.PSms;
import inf.um.psmultisign.PSsignature;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.RAND;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;

public class PsmsBlsSignature2022_PublicKeyVerifier extends PublicKeyVerifier<MSverfKey> {

    public PsmsBlsSignature2022_PublicKeyVerifier(MSverfKey publicKey) {

        super(publicKey, Curve.PSMS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        try {
            PabcSerializer.PSsignature protoSignature = PabcSerializer.PSsignature.parseFrom(signature);
            MSsignature sign = new PSsignature(protoSignature);
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
            MSauxArg auxArg=new PSauxArg(PsmsUmuUtils.PAIRING_NAME,digest.keySet());
            try {
                psScheme.setup(1, auxArg, PsmsUmuUtils.seed);
            } catch (MSSetupException e) {
                throw new RuntimeException(e);
            }
            MSmessage mAttr=new PSmessage(values,epoch);
            return psScheme.verf(this.getPublicKey(), mAttr, sign);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return false;
    }
}
