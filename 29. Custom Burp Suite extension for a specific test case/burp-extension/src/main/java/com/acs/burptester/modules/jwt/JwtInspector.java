package com.acs.burptester.modules.jwt;

import com.acs.burptester.core.TextJson;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class JwtInspector {

    private JwtInspector() {
    }

    public static Optional<Jwt> parse(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            String headerJson = decode(parts[0]);
            String payloadJson = decode(parts[1]);
            Map<String, Object> header = TextJson.parseObject(headerJson);
            Map<String, Object> payload = TextJson.parseObject(payloadJson);
            String alg = str(header.get("alg"));
            String typ = str(header.get("typ"));
            String kid = str(header.get("kid"));
            Long exp = num(payload.get("exp"));
            Long nbf = num(payload.get("nbf"));
            return Optional.of(new Jwt(headerJson, payloadJson, parts[2], alg, typ, kid, exp, nbf,
                    new LinkedHashMap<>(header), new LinkedHashMap<>(payload)));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static String encode(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    public static String decode(String segment) {
        return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static Long num(Object value) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        if (value instanceof String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}