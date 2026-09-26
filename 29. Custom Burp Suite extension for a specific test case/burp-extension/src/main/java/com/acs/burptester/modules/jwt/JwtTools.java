package com.acs.burptester.modules.jwt;

import com.acs.burptester.core.TextJson;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class JwtTools {

    private JwtTools() {
    }

    public static String buildUnsigned(String headerJson, String payloadJson) {
        return JwtInspector.encode(headerJson) + "." + JwtInspector.encode(payloadJson) + ".";
    }

    public static String sign(String headerJson, String payloadJson, String secret) {
        String signingInput = JwtInspector.encode(headerJson) + "." + JwtInspector.encode(payloadJson);
        byte[] mac = hmacSha256(secret.getBytes(StandardCharsets.UTF_8), signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(mac);
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    public static Map<String, Object> header(String alg, String typ, String kid) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("alg", alg);
        map.put("typ", typ);
        if (kid != null) {
            map.put("kid", kid);
        }
        return map;
    }

    public static String json(Map<String, Object> map) {
        return TextJson.stringify(map);
    }

    public static String kidPayload(String kid) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");
        header.put("kid", kid);
        return TextJson.stringify(header);
    }

    public static boolean indicatesAcceptance(int status, String body) {
        if (status == 401 || status == 403 || status == 400 || status == 500) {
            return false;
        }
        String lower = body.toLowerCase();
        return status >= 200 && status < 400
                && !lower.contains("unauthorized")
                && !lower.contains("forbidden");
    }

    public static String fingerprint(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}