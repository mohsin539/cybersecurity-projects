package com.mdmlite.agent;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

/**
 * Compliance evaluation, mirroring the desktop engine: severity-weighted score,
 * critical-fail gate, and a final COMPLIANT / NON_COMPLIANT verdict.
 */
public final class ComplianceEngine {

    private static int weight(String severity) {
        switch (severity == null ? "" : severity) {
            case "low":      return 1;
            case "medium":   return 2;
            case "high":     return 3;
            case "critical": return 4;
            default:         return 1;
        }
    }

    public static JSONObject evaluate(JSONObject telemetry) throws JSONException {
        List<BaselinePolicy.Rule> rules = BaselinePolicy.RULES;
        JSONArray results = new JSONArray();
        int totalW = 0, passW = 0, pass = 0, fail = 0, na = 0;
        boolean criticalFail = false;

        for (BaselinePolicy.Rule rule : rules) {
            boolean applicable = !rule.id.startsWith("ios");
            String verdict = "NA";
            String actual = "-";
            int w = weight(rule.severity);

            if (applicable) {
                switch (rule.kind) {
                    case "version_gte": {
                        String os = telemetry.optJSONObject("os").optString("version", "0.0");
                        actual = os;
                        verdict = atLeast(os, String.valueOf(rule.expected)) ? "PASS" : "FAIL";
                        break;
                    }
                    case "boolean": {
                        JSONObject sec = telemetry.optJSONObject("security");
                        String key = secKey(rule.id);
                        boolean val = sec != null && sec.optBoolean(key, false);
                        actual = String.valueOf(val);
                        boolean expected = Boolean.parseBoolean(String.valueOf(rule.expected));
                        verdict = val == expected ? "PASS" : "FAIL";
                        break;
                    }
                    case "allowlist": {
                        JSONObject apps = telemetry.optJSONObject("apps");
                        JSONArray installed = apps == null ? new JSONArray() : apps.optJSONArray("installed");
                        String[] required = (String[]) rule.expected;
                        JSONArray missing = new JSONArray();
                        for (String req : required) {
                            if (installed == null || !contains(installed, req)) missing.put(req);
                        }
                        actual = missing.length() == 0 ? "-" : missing.toString();
                        verdict = missing.length() == 0 ? "PASS" : "FAIL";
                        break;
                    }
                    case "denylist": {
                        JSONObject apps = telemetry.optJSONObject("apps");
                        JSONArray installed = apps == null ? new JSONArray() : apps.optJSONArray("installed");
                        String[] banned = (String[]) rule.expected;
                        JSONArray found = new JSONArray();
                        for (String b : banned) {
                            if (installed != null && contains(installed, b)) found.put(b);
                        }
                        actual = found.length() == 0 ? "-" : found.toString();
                        verdict = found.length() == 0 ? "PASS" : "FAIL";
                        break;
                    }
                    default:
                        verdict = "NA";
                }

                if ("PASS".equals(verdict)) { totalW += w; passW += w; pass++; }
                else if ("FAIL".equals(verdict)) { totalW += w; fail++;
                    if ("critical".equals(rule.severity)) criticalFail = true; }
                else na++;
            } else {
                na++;
            }

            results.put(new JSONObject()
                    .put("rule_id", rule.id)
                    .put("group", rule.group)
                    .put("label", rule.label)
                    .put("severity", rule.severity)
                    .put("verdict", verdict)
                    .put("expected", rule.expected)
                    .put("actual", actual));
        }

        double ratio = totalW == 0 ? 0.0 : (double) passW / totalW;
        boolean compliant = !criticalFail && ratio >= BaselinePolicy.THRESHOLD;

        return new JSONObject()
                .put("status", compliant ? "COMPLIANT" : "NON_COMPLIANT")
                .put("score", Math.round(ratio * 1000.0) / 10.0)
                .put("pass_count", pass)
                .put("fail_count", fail)
                .put("na_count", na)
                .put("threshold", BaselinePolicy.THRESHOLD * 100)
                .put("results", results);
    }

    private static String secKey(String ruleId) {
        switch (ruleId) {
            case "android.security.root":          return "rooted";
            case "android.security.encryption":    return "encryption";
            case "android.security.screenlock":    return "screen_lock";
            case "android.security.unknownsources":return "unknown_sources";
            case "android.security.playprotect":   return "play_protect";
            default:                               return "screen_lock";
        }
    }

    private static boolean contains(JSONArray arr, String needle) {
        for (int i = 0; i < arr.length(); i++) {
            if (needle.equals(arr.optString(i))) return true;
        }
        return false;
    }

    private static boolean atLeast(String actual, String minimum) {
        return compareVersion(actual, minimum) >= 0;
    }

    private static int compareVersion(String a, String b) {
        long[] va = versionParts(a);
        long[] vb = versionParts(b);
        for (int i = 0; i < 3; i++) {
            if (va[i] != vb[i]) return Long.compare(va[i], vb[i]);
        }
        return 0;
    }

    private static long[] versionParts(String v) {
        long[] out = new long[3];
        if (v == null) return out;
        String[] parts = v.replaceAll("[^0-9.]", "").split("\\.");
        for (int i = 0; i < parts.length && i < 3; i++) {
            try { out[i] = Long.parseLong(parts[i]); } catch (NumberFormatException ignore) { }
        }
        return out;
    }
}