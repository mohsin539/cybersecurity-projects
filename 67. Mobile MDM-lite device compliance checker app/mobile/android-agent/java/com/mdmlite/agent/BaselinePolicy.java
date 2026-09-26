package com.mdmlite.agent;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Embedded baseline policy, mirrored from the desktop checker
 * ("MDM-Lite Baseline Policy" v1.0.0). Enables standalone on-device verdicts.
 */
public final class BaselinePolicy {

    public static final String NAME = "MDM-Lite Baseline Policy";
    public static final String VERSION = "1.0.0";
    public static final double THRESHOLD = 0.80;

    public static final class Rule {
        public final String id;
        public final String group;
        public final String label;
        public final String severity;   // low | medium | high | critical
        public final String kind;       // version_gte | boolean | allowlist | denylist
        public final Object expected;

        Rule(String id, String group, String label, String severity, String kind, Object expected) {
            this.id = id;
            this.group = group;
            this.label = label;
            this.severity = severity;
            this.kind = kind;
            this.expected = expected;
        }
    }

    public static final List<Rule> RULES = build();

    private static List<Rule> build() {
        List<Rule> r = new ArrayList<>();
        // ---------------- android ----------------
        r.add(new Rule("android.os.version", "os", "Android OS version", "high", "version_gte", "12.0"));
        r.add(new Rule("android.security.root", "security", "Root / jailbreak detection", "critical", "boolean", false));
        r.add(new Rule("android.security.encryption", "security", "Full-disk / file encryption", "high", "boolean", true));
        r.add(new Rule("android.security.screenlock", "security", "Screen lock enforced", "medium", "boolean", true));
        r.add(new Rule("android.security.unknownsources", "security", "Unknown sources blocked", "high", "boolean", false));
        r.add(new Rule("android.security.playprotect", "security", "Google Play Protect", "medium", "boolean", true));
        r.add(new Rule("android.apps.required", "apps", "Required apps installed", "critical", "allowlist",
                new String[]{"com.google.android.gms"}));
        r.add(new Rule("android.apps.denylist", "apps", "Forbidden apps absent", "high", "denylist",
                new String[]{"com.example.roguespy", "org.torproject.android", "com.mxtech.videoplayer.ad"}));
        // ---------------- ios (informational on Android) ----------------
        r.add(new Rule("ios.os.version", "os", "iOS version", "high", "version_gte", "15.0"));
        r.add(new Rule("ios.security.jailbreak", "security", "Jailbreak detection", "critical", "boolean", false));
        return r;
    }

    @SuppressWarnings("unused")
    public static JSONArray rulesJson() throws JSONException {
        JSONArray arr = new JSONArray();
        for (Rule rule : RULES) {
            arr.put(new JSONObject()
                    .put("id", rule.id)
                    .put("group", rule.group)
                    .put("label", rule.label)
                    .put("severity", rule.severity)
                    .put("kind", rule.kind)
                    .put("expected", rule.expected));
        }
        return arr;
    }
}