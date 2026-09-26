package com.acs.burptester.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.acs.burptester.api.FacadeRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class Requests {

    private Requests() {
    }

    public static FacadeRequest toFacadeRequest(HttpRequest request) {
        List<String[]> headers = new ArrayList<>();
        for (var header : request.headers()) {
            headers.add(new String[]{header.name(), header.value()});
        }
        return new FacadeRequest(request.method(), request.url(), headers,
                request.bodyToString().getBytes(StandardCharsets.UTF_8));
    }

    public static FacadeRequest simpleGet(String url, String bearerToken) {
        List<String[]> headers = new ArrayList<>();
        headers.add(new String[]{"Authorization", "Bearer " + bearerToken});
        return new FacadeRequest("GET", url, headers, new byte[0]);
    }
}