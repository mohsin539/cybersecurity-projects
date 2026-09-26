package com.acs.launcher.core;

import com.acs.burptester.core.TextJson;
import com.acs.burptester.core.LoopbackControlServer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

public final class PairingClient {

    private PairingClient() {
    }

    public static PairingInfo loadPairing() throws IOException {
        Path pairingFile = LoopbackControlServer.pairingFile();
        if (!Files.exists(pairingFile)) {
            throw new IOException("Pairing file not found at " + pairingFile
                    + ". Load the extension in Burp Suite first.");
        }
        Map<String, Object> map = TextJson.parseObject(Files.readString(pairingFile, StandardCharsets.UTF_8));
        int port = number(map.get("port")).intValue();
        String token = String.valueOf(map.get("token"));
        return new PairingInfo(port, token);
    }

    public static void run(PairingInfo pairing, String testCaseId, Map<String, Object> profile,
                           String targetUrl, Consumer<Map<String, Object>> onMessage) throws IOException {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), pairing.port());
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("type", "run");
            request.put("token", pairing.token);
            request.put("testCaseId", testCaseId);
            request.put("targetUrl", targetUrl);
            request.put("profile", profile);
            writer.write(TextJson.stringify(request));
            writer.newLine();
            writer.flush();
            String line;
            while ((line = reader.readLine()) != null) {
                Map<String, Object> message = TextJson.parseObject(line);
                onMessage.accept(message);
                if ("done".equals(message.get("kind")) || "error".equals(message.get("kind"))) {
                    return;
                }
            }
        }
    }

    private static Number number(Object value) {
        if (value instanceof Number n) {
            return n;
        }
        if (value instanceof String s) {
            return Integer.parseInt(s);
        }
        throw new IllegalArgumentException("port missing from pairing file");
    }

    public record PairingInfo(int port, String token) {
    }
}