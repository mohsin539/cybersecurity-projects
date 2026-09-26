package com.acs.burptester.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public final class Hashes {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Hashes() {
    }

    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256(String data) {
        return sha256(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String chainHash(String prevHash, long timestampMillis, String payload) {
        return sha256(prevHash + "|" + timestampMillis + "|" + payload);
    }

    public static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}