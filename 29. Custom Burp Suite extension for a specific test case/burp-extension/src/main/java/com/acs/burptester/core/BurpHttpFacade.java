package com.acs.burptester.core;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.FacadeResponse;
import com.acs.burptester.api.HttpFacade;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class BurpHttpFacade implements HttpFacade {

    private final Http http;

    public BurpHttpFacade(Http http) {
        this.http = http;
    }

    @Override
    public FacadeResponse send(FacadeRequest request) {
        HttpRequest burpRequest = HttpRequest.httpRequestFromUrl(request.url());
        burpRequest = burpRequest.withMethod(request.method());
        for (String[] header : request.headers()) {
            burpRequest = burpRequest.withUpdatedHeader(header[0], header[1]);
        }
        if (request.body() != null && request.body().length > 0) {
            burpRequest = burpRequest.withBody(new String(request.body(), StandardCharsets.UTF_8));
        }
        long start = System.currentTimeMillis();
        HttpRequestResponse response = http.sendRequest(burpRequest);
        long elapsed = System.currentTimeMillis() - start;
        HttpResponse burpResponse = response.response();
        List<String[]> headers = new ArrayList<>();
        for (var header : burpResponse.headers()) {
            headers.add(new String[]{header.name(), header.value()});
        }
        return new FacadeResponse(burpResponse.statusCode(), headers,
                burpResponse.bodyToString().getBytes(StandardCharsets.UTF_8), elapsed);
    }
}