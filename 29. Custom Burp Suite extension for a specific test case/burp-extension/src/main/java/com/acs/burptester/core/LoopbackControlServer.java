package com.acs.burptester.core;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.HttpFacade;
import com.acs.burptester.api.TestProfile;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class LoopbackControlServer {

    private static final Path PAIRING_DIR = Path.of(System.getProperty("user.home"), ".burptester");
    private static final Path PAIRING_FILE = PAIRING_DIR.resolve("pairing.json");
    private static final AtomicBoolean started = new AtomicBoolean(false);

    private LoopbackControlServer() {
    }

    public static void start(TestCaseEngine engine, HttpFacade http) {
        if (!started.compareAndSet(false, true)) {
            return;
        }
        Thread server = new Thread(() -> bindLoop(engine, http), "burptester-loopback");
        server.setDaemon(true);
        server.start();
    }

    private static void bindLoop(TestCaseEngine engine, HttpFacade http) {
        String token = Hashes.randomToken();
        try (ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            serverSocket.setReuseAddress(false);
            writePairingFile(serverSocket.getLocalPort(), token);
            ExecutorService workers = Executors.newCachedThreadPool();
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Socket socket = serverSocket.accept();
                    workers.submit(() -> handle(engine, http, socket, token));
                } catch (Exception e) {
                    return;
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Loopback control server failed to start", e);
        }
    }

    private static void writePairingFile(int port, String token) {
        try {
            Files.createDirectories(PAIRING_DIR);
            Map<String, Object> pairing = new LinkedHashMap<>();
            pairing.put("port", port);
            pairing.put("token", token);
            Path temp = PAIRING_DIR.resolve("pairing.json.tmp");
            Files.writeString(temp, TextJson.stringify(pairing), StandardCharsets.UTF_8);
            Files.move(temp, PAIRING_FILE, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to write pairing file", e);
        }
    }

    private static void handle(TestCaseEngine engine, HttpFacade http, Socket socket, String expectedToken) {
        try (socket;
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            if (line == null) {
                return;
            }
            Map<String, Object> message = TextJson.parseObject(line);
            if (!expectedToken.equals(message.get("token"))) {
                reply(writer, Map.of("kind", "error", "message", "bad token"));
                return;
            }
            String type = String.valueOf(message.get("type"));
            if (!"run".equals(type)) {
                reply(writer, Map.of("kind", "error", "message", "unknown type " + type));
                return;
            }
            TestProfile profile = Profiles.fromJson(TextJson.stringify(message.get("profile")));
            String targetUrl = strField(message, "targetUrl");
            String bearer = strField(profile.tokens(), 0);
            FacadeRequest target = Requests.simpleGet(targetUrl, bearer);
            Runner.run(engine, strField(message, "testCaseId"), profile, target, http,
                    progress -> safeReply(writer, Map.of("kind", "status", "message", String.valueOf(progress))),
                    stream -> safeReply(writer, stream));
        } catch (Exception e) {
            System.err.println("BurpTester loopback client error: " + e);
        }
    }

    private static String strField(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private static String strField(java.util.List<?> list, int index) {
        if (list == null || list.isEmpty() || index >= list.size()) {
            return "";
        }
        return String.valueOf(list.get(index));
    }

    private static void reply(BufferedWriter writer, Map<String, Object> payload) throws java.io.IOException {
        writer.write(TextJson.stringify(payload));
        writer.newLine();
        writer.flush();
    }

    private static void safeReply(BufferedWriter writer, Map<String, Object> payload) {
        try {
            reply(writer, payload);
        } catch (java.io.IOException e) {
            throw new RuntimeException("loopback write failed", e);
        }
    }

    public static Path pairingFile() {
        return PAIRING_FILE;
    }
}