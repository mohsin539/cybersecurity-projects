package com.acs.burptester.api;

public record FacadeRequest(String method, String url, java.util.List<String[]> headers, byte[] body) {

    public FacadeRequest {
        headers = java.util.List.copyOf(headers);
    }

    public FacadeRequest withHeader(String name, String value) {
        java.util.List<String[]> updated = new java.util.ArrayList<>();
        boolean replaced = false;
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                updated.add(new String[]{h[0], value});
                replaced = true;
            } else {
                updated.add(h);
            }
        }
        if (!replaced) {
            updated.add(new String[]{name, value});
        }
        return new FacadeRequest(method, url, updated, body);
    }

    public String headerValue(String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }
}