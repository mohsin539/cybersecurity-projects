package com.acs.burptester.core;

import com.acs.burptester.api.TestProfile;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Profiles {

    private Profiles() {
    }

    public static TestProfile fromJson(String json) {
        Map<String, Object> map = TextJson.parseObject(json);
        String id = str(map.get("id"), "default");
        String name = str(map.get("name"), "Default BurpTester profile");
        boolean dryRun = bool(map.get("dryRun"), true);
        int maxRequests = intVal(map.get("maxRequests"), 20);
        long delay = longVal(map.get("interRequestDelayMillis"), 250L);
        List<String> testCases = stringList(map.get("testCaseIds"));
        List<String> tokens = stringList(map.get("tokens"));
        return new TestProfile(id, name, dryRun, maxRequests, delay, testCases, tokens);
    }

    public static Map<String, Object> toMap(TestProfile profile) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", profile.id());
        map.put("name", profile.name());
        map.put("dryRun", profile.dryRun());
        map.put("maxRequests", profile.maxRequests());
        map.put("interRequestDelayMillis", profile.interRequestDelayMillis());
        map.put("testCaseIds", profile.testCaseIds());
        map.put("tokens", profile.tokens());
        return map;
    }

    private static String str(Object value, String fallback) {
        return value == null ? fallback : String.valueOf(value);
    }

    private static boolean bool(Object value, boolean fallback) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof String s) {
            return Boolean.parseBoolean(s);
        }
        return fallback;
    }

    private static int intVal(Object value, int fallback) {
        if (value instanceof Number n) {
            return n.intValue();
        }
        if (value instanceof String s) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }

    private static long longVal(Object value, long fallback) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        if (value instanceof String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }

    private static List<String> stringList(Object value) {
        if (value instanceof List<?> raw) {
            return raw.stream().map(Object::toString).toList();
        }
        return List.of();
    }
}