package com.mdmlite.agent;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Posts a telemetry/report payload to the MDM-Lite desktop checker over HTTP. */
public final class Sender {

    public static final class Result {
        public final boolean ok;
        public final String body;

        Result(boolean ok, String body) {
            this.ok = ok;
            this.body = body;
        }
    }

    public static Result send(String endpoint, JSONObject payload, int timeoutMs) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setDoOutput(true);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);

            byte[] out = payload.toString().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(out.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(out);
            }

            int code = conn.getResponseCode();
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            String body = readAll(is);
            boolean ok = code >= 200 && code < 300;
            return new Result(ok, code + ": " + body);
        } catch (Exception e) {
            return new Result(false, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }
}