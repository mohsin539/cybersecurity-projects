package com.acs.burptester.modules.jwt;

import java.util.Map;

public record Jwt(
        String headerJson,
        String payloadJson,
        String signature,
        String alg,
        String typ,
        String kid,
        Long exp,
        Long nbf,
        Map<String, Object> headerClaims,
        Map<String, Object> payloadClaims) {

    public String compact() {
        java.util.Base64.Encoder enc = java.util.Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString(headerJson.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + enc.encodeToString(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + signature;
    }
}