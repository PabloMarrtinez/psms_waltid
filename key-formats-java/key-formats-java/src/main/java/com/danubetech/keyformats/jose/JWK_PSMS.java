package com.danubetech.keyformats.jose;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.Map;
import java.util.Objects;

public class JWK_PSMS {

    private static final ObjectMapper objectMapper = new ObjectMapper();


    @JsonProperty("y_m") private String y_m;
    @JsonProperty("epoch") private String epoch;
    @JsonProperty("vx") private String vx;
    @JsonProperty("vy") private String vy;
    @JsonProperty("vy_m") private String vy_m;
    @JsonProperty("vy_epoch") private String vy_epoch;
    @JsonProperty("kty") private String kty;
    @JsonProperty("crv") private String crv;
    @JsonProperty("x") private String x;
    @JsonProperty("y") private String y;

    public JWK_PSMS(){

    }
    public static JWK_PSMS fromJson(String json) throws IOException {
        return objectMapper.readValue(json, JWK_PSMS.class);
    }

    public static JWK_PSMS fromJson(Reader reader) throws IOException {
        return objectMapper.readValue(reader, JWK_PSMS.class);
    }

    public static JWK_PSMS fromMap(Map<String, Object> map) {
        return objectMapper.convertValue(map, JWK_PSMS.class);
    }

    public Map<String, Object> toMap() {
        return objectMapper.convertValue(this, Map.class);
    }

    public String toJson() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWK_PSMS jwk_psm = (JWK_PSMS) o;
        return Objects.equals(y_m, jwk_psm.y_m) &&
                Objects.equals(epoch, jwk_psm.epoch) &&
                // ... (compare other fields) ...
                Objects.equals(y, jwk_psm.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(y_m, epoch, vx, vy, vy_m, vy_epoch, kty, crv, x, y);
    }

    @Override
    public String toString() {
        return "JWK_PSMS{" +
                "y_m='" + y_m + '\'' +
                ", epoch='" + epoch + '\'' +
                // ... (include other fields) ...
                ", y='" + y + '\'' +
                '}';
    }

    // GETTERS AND SETTERS


    public String getY_m() {
        return y_m;
    }

    public void setY_m(String y_m) {
        this.y_m = y_m;
    }

    public String getEpoch() {
        return epoch;
    }

    public void setEpoch(String epoch) {
        this.epoch = epoch;
    }

    public String getVx() {
        return vx;
    }

    public void setVx(String vx) {
        this.vx = vx;
    }

    public String getVy() {
        return vy;
    }

    public void setVy(String vy) {
        this.vy = vy;
    }

    public String getVy_m() {
        return vy_m;
    }

    public void setVy_m(String vy_m) {
        this.vy_m = vy_m;
    }

    public String getVy_epoch() {
        return vy_epoch;
    }

    public void setVy_epoch(String vy_epoch) {
        this.vy_epoch = vy_epoch;
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

    public String getX() {
        return x;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    public void setY(String y) {
        this.y = y;
    }
}