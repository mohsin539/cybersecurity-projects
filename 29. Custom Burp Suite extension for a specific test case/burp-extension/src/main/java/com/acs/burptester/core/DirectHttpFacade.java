package com.acs.burptester.core;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.FacadeResponse;
import com.acs.burptester.api.HttpFacade;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class DirectHttpFacade implements HttpFacade {

    private final HttpClient client;

    public DirectHttpFacade() {
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public FacadeResponse send(FacadeRequest request) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(request.url()))
                    .timeout(Duration.ofSeconds(15));
            for (String[] header : request.headers()) {
                builder.header(header[0], header[1]);
            }
            if (request.body() != null && request.body().length > 0) {
                CharSequence body = new String(request.body(), java.nio.charset.StandardCharsets.UTF_8);
                builder.method(request.method(), HttpRequest.BodyPublishers.ofString(body.toString()));
            } else {
                builder.method(request.method(), HttpRequest.BodyPublishers.noBody());
            }
            long start = System.currentTimeMillis();
            HttpResponse<byte[]> response = client.send(builder.build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            long elapsed = System.currentTimeMillis() - start;
            List<String[]> headers = new ArrayList<>();
            response.headers().map().forEach((name, values) -> values.forEach(value ->
                    headers.add(new String[]{name, value})));
            return new FacadeResponse(response.statusCode(), headers, response.body(), elapsed);
        } catch (Exception e) {
            return new FacadeResponse(0, List.of(), e.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8), 0);
        }
    }
}