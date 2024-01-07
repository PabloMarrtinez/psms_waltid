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

public class PsmsBlsSignatureProof2022_PublicKeyVerifier extends PublicKeyVerifier<MSverfKey> {

    public PsmsBlsSignatureProof2022_PublicKeyVerifier(MSverfKey publicKey) {

        super(publicKey, Curve.PSMS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {



        return false;
    }
}