package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.JWK_to_PrivateKey;
import com.danubetech.keyformats.JWK_to_PublicKey;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import inf.um.multisign.MS;
import inf.um.multisign.MSauxArg;
import inf.um.multisign.MSprivateKey;
import inf.um.multisign.MSverfKey;
import inf.um.psmultisign.PSauxArg;
import inf.um.psmultisign.PSms;
import inf.um.util.Pair;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PsmsBlsSignature2022Test extends AbstractTest{

     static final JWK jwkPublic;

     static final JWK jwkPrivate;

    static final JWK jwkPublic2;

    static final JWK jwkPrivate2;

    static {
        try {
            jwkPublic = JWK.fromJson("""
                        {
                        "kty": "EC",
                        "crv": "PsmsBlsSignature2022Proof",
                        "pk": "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"
                        }
                    """);

            jwkPublic2 = JWK.fromJson("""
                        {
                        "kty": "EC",
                        "crv": "PsmsBlsSignature2022Proof",
                        "pk": "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"
                        }
                    """);

            jwkPrivate = JWK.fromJson("""
                    {
                    "kty": "EC",
                    "crv": "PsmsBlsSignature2022Proof",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAQ7RL72G1h3eINoxp/0bkUUwBDUeNTvOukhJOxmKL8RSNHDEd3HXg==",
                    "y_m": "AAAAAAAAAAAAAAAAAAAAAAAAAA0AsmoZkWwBkwfJgPrEql0rqsd4JvDOpyVuT/x9HQ89Dshw+wOq5w==",
                    "epoch": "AAAAAAAAAAAAAAAAAAAAAAAAAAJo45kOflpd3GSgodbcrOhPtMzWxdAav/A2g/S8PzpcHf9kP/7h0w==",
                    "y": "{\\\"https://w3id.org/citizenship#residentSince\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAAeON7RcXTRtz+tNcOBzC5NDgVuHznnR4v638HcF9r6/q87dSmR3g==\\\",\\\"https://w3id.org/citizenship#lprCategory\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAM4mFd+lRPgKdsL9Hc3uhKw+w6wPMdbkQTLlfspb2N2Dsg4oLF5lA==\\\",\\\"https://www.w3.org/2018/credentials#issuer\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAANODbS6YoEgkXFu+WRHPJq36PuadTZvotnXcMZp0ScIriZCjIdMUw==\\\",\\\"https://www.w3.org/2018/credentials#issuanceDate\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAA6diLhheMnNoDVD+gC/QFdnYN4xbOg+mIYqSNhc5tPvqXEkN0hFKA==\\\",\\\"https://w3id.org/citizenship#lprNumber\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAALbIZbdH53Z/N0k5OcpyK0MgXt+qA6G7BMfwulyzrJZM7toKU/o8Q==\\\",\\\"https://w3id.org/citizenship#commuterClassification\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAdni/jt2bwqOAdw4vMMzxDJWYBQfiYsBnxz7sBfHUDYbb+ypZTQNQ==\\\",\\\"http://schema.org/givenName\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAhNrPBJlS/V/jjJP+92c9Z0lLKayRBSP3NDD45i0OXRLYUDNu44vQ==\\\",\\\"https://www.w3.org/2018/credentials#expirationDate\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAO9WBQ5wpIPTQhqD/JU7aS5KtaoSgcBvrtb4ECJg/RKB8j8LHZrhQ==\\\",\\\"http://schema.org/image\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAv6LfNPhdn/yV7LuK3OoZvbRIOcmVZdT3vSkD4TmlCDt87onHEwdQ==\\\",\\\"https://w3id.org/citizenship#birthCountry\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAyUFwNCyzXtt7dMqqkqHb9L1Q4c/rXQc3Xb3on8xkeKvsJBgNFmbw==\\\",\\\"http://schema.org/description\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAv+10UXfshZinzmBb++aQ0xtYRaOwz0HtjDgzPcfqT43X51R/85bw==\\\",\\\"http://schema.org/name\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAR+4rGjm0OTX7i6y7OneDzz3qb06UV2WUTh988ABPU5+UJIc3wEcw==\\\",\\\"http://schema.org/familyName\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAb49pzR0tpiQyCKg4W2pCa24N89zcEV2Xgm3jBep/hDZBNjbe906w==\\\",\\\"http://schema.org/birthDate\\\":\\\"AAAAAAAAAAAAAAAAAAAAAAAAAAbB9wXZBWHkfesn9n1HCoE0DkWpl5rlyk3nxvWiu297AyGWwfzDCA==\\\",\\\"http://schema.org/gender\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAryNujcBQpXmlwbr75AsWYHpkN6IMq+UqV1jP1b5LbsE59hKIDQZw==\\\",\\\"https://www.w3.org/2018/credentials#credentialSubject\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAUXUlj/cwpQ6qnZTdyka8P/veCTC11Q55HKg8slSrf1U0gNNTsyrg==\\\"}"
                    }""");


            jwkPrivate2 = JWK.fromJson("""
                    {
                    "kty": "EC",
                    "crv": "PsmsBlsSignature2022Proof",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAQ7RL72G1h3eINoxp/0bkUUwBDUeNTvOukhJOxmKL8RSNHDEd3HXg==",
                    "y_m": "AAAAAAAAAAAAAAAAAAAAAAAAAA0AsmoZkWwBkwfJgPrEql0rqsd4JvDOpyVuT/x9HQ89Dshw+wOq5w==",
                    "epoch": "AAAAAAAAAAAAAAAAAAAAAAAAAAJo45kOflpd3GSgodbcrOhPtMzWxdAav/A2g/S8PzpcHf9kP/7h0w==",
                    "y": "{\\\"https://w3id.org/citizenship#residentSince\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAAeON7RcXTRtz+tNcOBzC5NDgVuHznnR4v638HcF9r6/q87dSmR3g==\\\",\\\"https://w3id.org/citizenship#lprCategory\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAM4mFd+lRPgKdsL9Hc3uhKw+w6wPMdbkQTLlfspb2N2Dsg4oLF5lA==\\\",\\\"https://w3id.org/citizenship#lprNumber\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAANODbS6YoEgkXFu+WRHPJq36PuadTZvotnXcMZp0ScIriZCjIdMUw==\\\",\\\"https://w3id.org/citizenship#commuterClassification\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAhNrPBJlS/V/jjJP+92c9Z0lLKayRBSP3NDD45i0OXRLYUDNu44vQ==\\\",\\\"http://schema.org/givenName\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAO9WBQ5wpIPTQhqD/JU7aS5KtaoSgcBvrtb4ECJg/RKB8j8LHZrhQ==\\\",\\\"http://schema.org/image\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAv6LfNPhdn/yV7LuK3OoZvbRIOcmVZdT3vSkD4TmlCDt87onHEwdQ==\\\",\\\"https://w3id.org/citizenship#birthCountry\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAyUFwNCyzXtt7dMqqkqHb9L1Q4c/rXQc3Xb3on8xkeKvsJBgNFmbw==\\\",\\\"http://schema.org/familyName\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAA6diLhheMnNoDVD+gC/QFdnYN4xbOg+mIYqSNhc5tPvqXEkN0hFKA==\\\",\\\"http://schema.org/birthDate\\\":\\\"AAAAAAAAAAAAAAAAAAAAAAAAAALbIZbdH53Z/N0k5OcpyK0MgXt+qA6G7BMfwulyzrJZM7toKU/o8Q==\\\",\\\"http://schema.org/gender\\\": \\\"AAAAAAAAAAAAAAAAAAAAAAAAAAdni/jt2bwqOAdw4vMMzxDJWYBQfiYsBnxz7sBfHUDYbb+ypZTQNQ==\\\"}"
                    }""");

        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }


    @Override
    KeyTypeName getKeyTypeName() {
        return KeyTypeName.PsmsBlsSignature2022;
    }

    @Override
    List<String> getAlgorithms() {
        return Collections.singletonList(JWSAlgorithm.PSMSAlg);
    }

    @Override
    Object getPrivateKey() {
        //return null;
        return JWK_to_PrivateKey.JWK_to_PsmsBlsPrivateKey(jwkPrivate2);
    }

    @Override
    Object getPublicKey() {
        //return null;
        return JWK_to_PublicKey.JWK_to_Psms_PublicKey(jwkPublic2
        );
    }


    @Test
    public void testPublicKey() throws Exception {
        MS psScheme=new PSms();
        Set<String> attrNames=new HashSet<>(Arrays.asList(
                "http://schema.org/birthDate",
                "http://schema.org/familyName",
                "http://schema.org/gender",
                "http://schema.org/givenName",
                "http://schema.org/image",
                "https://w3id.org/citizenship#birthCountry",
                "https://w3id.org/citizenship#commuterClassification",
                "https://w3id.org/citizenship#lprCategory",
                "https://w3id.org/citizenship#lprNumber",
                "https://w3id.org/citizenship#residentSince",
                "http://schema.org/description",
                "http://schema.org/name",
                "https://www.w3.org/2018/credentials#issuanceDate",
                "https://www.w3.org/2018/credentials#credentialSubject",
                "https://www.w3.org/2018/credentials#expirationDate",
                "https://www.w3.org/2018/credentials#issuer"));

        Set<String> attrNames_credential_subject =new HashSet<>(Arrays.asList(
                "http://schema.org/birthDate",
                "http://schema.org/familyName",
                "http://schema.org/gender",
                "http://schema.org/givenName",
                "http://schema.org/image",
                "https://w3id.org/citizenship#birthCountry",
                "https://w3id.org/citizenship#commuterClassification",
                "https://w3id.org/citizenship#lprCategory",
                "https://w3id.org/citizenship#lprNumber",
                "https://w3id.org/citizenship#residentSince"
        ));

        String PAIRING_NAME="inf.um.pairingBLS461.PairingBuilderBLS461";
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames_credential_subject);
        psScheme.setup(1,auxArg, "seed".getBytes());
        Pair<MSprivateKey, MSverfKey> keys=psScheme.kg();
        byte[] publicKey1 = keys.getSecond().getEncoded();

        MSverfKey publicKey = JWK_to_PublicKey.JWK_to_Psms_PublicKey(jwkPublic2);
        byte[] publicKey2 = publicKey.getEncoded();
        boolean areEqual = Arrays.equals(publicKey1, publicKey2);
        assertTrue(areEqual);
    }
}
