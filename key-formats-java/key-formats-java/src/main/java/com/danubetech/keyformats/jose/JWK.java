package com.danubetech.keyformats.jose;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.*;

public class JWK {
    @JsonProperty("kid") private String kid;
    @JsonProperty("use") private String use;
    @JsonProperty("key_ops") private String key_ops;
    @JsonProperty("alg") private String alg;
    @JsonProperty("kty") private String kty;
    @JsonProperty("crv") private String crv;
    @JsonProperty("x5u") private String x5u;
    @JsonProperty("x5c") private List<String> x5c;
    @JsonProperty("x5t") private String x5t;
    @JsonProperty("x5t#S256") private String x5t_S256;
    @JsonProperty("x") private String x;
    @JsonProperty("y") private String y;
    @JsonProperty("d") private String d;
    @JsonProperty("n") private String n;
    @JsonProperty("e") private String e;
    @JsonProperty("k") private String k;
    @JsonProperty("p") private String p;
    @JsonProperty("q") private String q;
    @JsonProperty("dp") private String dp;
    @JsonProperty("dq") private String dq;
    @JsonProperty("qi") private String qi;

    @JsonProperty("y_m") private String y_m;

    @JsonProperty("epoch") private String epoch;

    @JsonProperty("vx") private String vx;

    @JsonProperty("vy") private String vy;

    @JsonProperty("vy_m") private String vy_m;

    @JsonProperty("vy_epoch") private String vy_epoch;

    @JsonProperty("pk") private String public_key;

    public String getPublic_key() {
        return public_key;
    }

    public void setPublic_key(String public_key) {
        this.public_key = public_key;
    }

    public String getY_m() {
        return y_m;
    }

    public String getEpoch() {
        return epoch;
    }


    public String getVx() {
        return vx;
    }


    public String getVy_m() {
        return vy_m;
    }

    public String getVy_epoch() {
        return vy_epoch;
    }

    public JWK() {
    }

    /*
     * Serialization
     */

    private static final ObjectMapper objectMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public static JWK fromJson(String json) throws IOException {
        return objectMapper.readValue(json, JWK.class);
    }

    public static JWK fromJson(Reader reader) throws IOException {
        return objectMapper.readValue(reader, JWK.class);
    }

    public static JWK fromMap(Map<String, Object> map) throws IOException {
        return objectMapper.convertValue(map, JWK.class);
    }

    public Map<String, Object> toMap() {
        return objectMapper.convertValue(this, LinkedHashMap.class);
    }

    public String toJson() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Cannot write JSON: " + ex.getMessage(), ex);
        }
    }

    @Deprecated
    public static JWK parse(Map<String, Object> json) {
        return objectMapper.convertValue(json, JWK.class);
    }

    @Deprecated
    public static JWK parse(String string) throws IOException {
        return objectMapper.readValue(new StringReader(string), JWK.class);
    }

    @Deprecated
    public String toJSONString() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    /*
     * Getters and setters
     */

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKey_ops() {
        return key_ops;
    }

    public void setKey_ops(String key_ops) {
        this.key_ops = key_ops;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX5u() {
        return x5u;
    }

    public void setX5u(String x5u) {
        this.x5u = x5u;
    }

    public List<String> getX5c() {
        return x5c;
    }

    public void setX5c(List<String> x5c) {
        this.x5c = x5c;
    }

    public String getX5t() {
        return x5t;
    }

    public void setX5t(String x5t) {
        this.x5t = x5t;
    }

    public String getX5t_S256() {
        return x5t_S256;
    }

    public void setX5t_S256(String x5t_S256) {
        this.x5t_S256 = x5t_S256;
    }

    public String getX() {
        return x;
    }

    @JsonIgnore
    public byte[] getXdecoded() {
        String x = this.getX();
        return x != null ? Base64.getUrlDecoder().decode(x) : null;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    @JsonIgnore
    public byte[] getYdecoded() {
        String y = this.getY();
        return y != null ? Base64.getUrlDecoder().decode(y) : null;
    }

    public void setY(String y) {
        this.y = y;
    }

    public String getD() {
        return d;
    }

    @JsonIgnore
    public byte[] getDdecoded() {
        String d = this.getD();
        return d != null ? Base64.getUrlDecoder().decode(d) : null;
    }

    public void setD(String d) {
        this.d = d;
    }

    public String getN() {
        return n;
    }

    @JsonIgnore
    public byte[] getNdecoded() {
        String n = this.getN();
        return n != null ? Base64.getUrlDecoder().decode(n) : null;
    }

    public void setN(String n) {
        this.n = n;
    }

    public String getE() {
        return e;
    }

    @JsonIgnore
    public byte[] getEdecoded() {
        String e = this.getE();
        return e != null ? Base64.getUrlDecoder().decode(e) : null;
    }

    public void setE(String e) {
        this.e = e;
    }

    public String getK() {
        return k;
    }

    @JsonIgnore
    public byte[] getKdecoded() {
        String k = this.getK();
        return k != null ? Base64.getUrlDecoder().decode(k) : null;
    }

    public void setK(String k) {
        this.k = k;
    }

    public String getP() {
        return p;
    }

    @JsonIgnore
    public byte[] getPdecoded() {
        String p = this.getP();
        return p != null ? Base64.getUrlDecoder().decode(p) : null;
    }

    public void setP(String p) {
        this.p = p;
    }

    public String getQ() {
        return q;
    }

    @JsonIgnore
    public byte[] getQdecoded() {
        String q = this.getQ();
        return q != null ? Base64.getUrlDecoder().decode(q) : null;
    }

    public void setQ(String q) {
        this.q = q;
    }

    public String getDp() {
        return dp;
    }

    @JsonIgnore
    public byte[] getDpdecoded() {
        String dp = this.getDp();
        return dp != null ? Base64.getUrlDecoder().decode(dp) : null;
    }

    public void setDp(String dp) {
        this.dp = dp;
    }

    public String getDq() {
        return dq;
    }

    @JsonIgnore
    public byte[] getDqdecoded() {
        String dq = this.getDq();
        return dq != null ? Base64.getUrlDecoder().decode(dq) : null;
    }

    public void setDq(String dq) {
        this.dq = dq;
    }

    public String getQi() {
        return qi;
    }

    @JsonIgnore
    public byte[] getQidecoded() {
        String qi = this.getQi();
        return qi != null ? Base64.getUrlDecoder().decode(qi) : null;
    }

    public void setQi(String qi) {
        this.qi = qi;
    }

    /*
     * Object methods
     */

    @Override
    public String toString() {
        return "JWK{" +
                "kid='" + kid + '\'' +
                ", use='" + use + '\'' +
                ", key_ops='" + key_ops + '\'' +
                ", alg='" + alg + '\'' +
                ", kty='" + kty + '\'' +
                ", crv='" + crv + '\'' +
                ", x5u='" + x5u + '\'' +
                ", x5c=" + x5c +
                ", x5t='" + x5t + '\'' +
                ", x5t_S256='" + x5t_S256 + '\'' +
                ", x='" + x + '\'' +
                ", y='" + y + '\'' +
                ", d='" + d + '\'' +
                ", n='" + n + '\'' +
                ", e='" + e + '\'' +
                ", k='" + k + '\'' +
                ", p='" + p + '\'' +
                ", q='" + q + '\'' +
                ", dp='" + dp + '\'' +
                ", dq='" + dq + '\'' +
                ", qi='" + qi + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWK jwk = (JWK) o;
        return Objects.equals(kid, jwk.kid) && Objects.equals(use, jwk.use) && Objects.equals(key_ops, jwk.key_ops) && Objects.equals(alg, jwk.alg) && Objects.equals(kty, jwk.kty) && Objects.equals(crv, jwk.crv) && Objects.equals(x5u, jwk.x5u) && Objects.equals(x5c, jwk.x5c) && Objects.equals(x5t, jwk.x5t) && Objects.equals(x5t_S256, jwk.x5t_S256) && Objects.equals(x, jwk.x) && Objects.equals(y, jwk.y) && Objects.equals(d, jwk.d) && Objects.equals(n, jwk.n) && Objects.equals(e, jwk.e) && Objects.equals(k, jwk.k) && Objects.equals(p, jwk.p) && Objects.equals(q, jwk.q) && Objects.equals(dp, jwk.dp) && Objects.equals(dq, jwk.dq) && Objects.equals(qi, jwk.qi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kid, use, key_ops, alg, kty, crv, x5u, x5c, x5t, x5t_S256, x, y, d, n, e, k, p, q, dp, dq, qi);
    }
}
