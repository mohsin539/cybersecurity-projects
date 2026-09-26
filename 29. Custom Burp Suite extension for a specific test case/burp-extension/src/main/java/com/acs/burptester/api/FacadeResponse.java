package com.acs.burptester.api;

public record FacadeResponse(int status, java.util.List<String[]> headers, byte[] body, long roundTripMillis) {

    public FacadeResponse {
        headers = java.util.List.copyOf(headers);
    }

    public String bodyText() {
        return new String(body, java.nio.charset.StandardCharsets.UTF_8);
    }

    public static FacadeResponse of(int status, String bodyText) {
        return new FacadeResponse(status, java.util.List.of(), bodyText.getBytes(java.nio.charset.StandardCharsets.UTF_8), 0);
    }
}