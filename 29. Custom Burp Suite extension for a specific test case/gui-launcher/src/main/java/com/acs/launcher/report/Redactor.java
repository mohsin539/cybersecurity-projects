package com.acs.launcher.report;

import java.util.List;

public final class Redactor {

    private Redactor() {
    }

    public static String redact(List<String> secrets, String text) {
        String out = text == null ? "" : text;
        for (String secret : secrets) {
            String s = secret == null ? "" : secret.trim();
            if (!s.isEmpty() && out.contains(s)) {
                out = out.replace(s, "[REDACTED]");
            }
        }
        return out;
    }
}