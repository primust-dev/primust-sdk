package com.primust.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP transport for Primust API. Raw data never transits —
 * only commitment hashes and bounded metadata.
 *
 * Falls back to local queue when API is unreachable. Returns null
 * to indicate queued (caller handles graceful degradation).
 */
class HttpTransport {

    private static final Logger log = Logger.getLogger("primust.transport");

    private final String apiKey;
    private final String baseUrl;
    private final HttpClient client;

    HttpTransport(String apiKey, String baseUrl) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl.endsWith("/api/v1")
                ? baseUrl : baseUrl + "/api/v1";
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    Map<String, Object> postOpenRun(Map<String, Object> payload) {
        return post("/runs", payload);
    }

    Map<String, Object> postRecord(String runId, Map<String, Object> envelope) {
        return post("/runs/" + runId + "/records", envelope);
    }

    Map<String, Object> postCloseRun(String runId, Map<String, Object> payload) {
        return post("/runs/" + runId + "/close", payload);
    }

    Map<String, Object> postManifest(Map<String, Object> manifest) {
        return post("/manifests", manifest);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> post(String path, Map<String, Object> body) {
        try {
            String json = toJson(body);
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .timeout(Duration.ofSeconds(30))
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                return parseJson(resp.body());
            }
            log.warning("Primust API returned " + resp.statusCode() + ": " + resp.body());
            return null; // queued
        } catch (IOException | InterruptedException e) {
            log.log(Level.WARNING, "Primust API unreachable — record queued", e);
            return null; // queued
        }
    }

    // Minimal JSON serializer — no external dependencies
    static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String s) return "\"" + escapeJson(s) + "\"";
        if (obj instanceof Number || obj instanceof Boolean) return obj.toString();
        if (obj instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            // Sort keys for determinism
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) keys.add(String.valueOf(k));
            Collections.sort(keys);
            for (String key : keys) {
                if (!first) sb.append(",");
                sb.append("\"").append(escapeJson(key)).append("\":").append(toJson(map.get(key)));
                first = false;
            }
            return sb.append("}").toString();
        }
        if (obj instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(toJson(list.get(i)));
            }
            return sb.append("]").toString();
        }
        return "\"" + escapeJson(obj.toString()) + "\"";
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // Minimal JSON parser — returns Map<String, Object> for top-level objects
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseJson(String json) {
        if (json == null || json.isBlank()) return Map.of();
        json = json.trim();
        if (!json.startsWith("{")) return Map.of("raw", json);
        // Use a simple recursive descent for the common cases we need
        try {
            return (Map<String, Object>) parseValue(json, new int[]{0});
        } catch (Exception e) {
            return Map.of("raw", json);
        }
    }

    private static Object parseValue(String json, int[] pos) {
        skipWhitespace(json, pos);
        if (pos[0] >= json.length()) return null;
        char c = json.charAt(pos[0]);
        if (c == '{') return parseObject(json, pos);
        if (c == '[') return parseArray(json, pos);
        if (c == '"') return parseString(json, pos);
        if (c == 't' || c == 'f') return parseBoolean(json, pos);
        if (c == 'n') { pos[0] += 4; return null; }
        return parseNumber(json, pos);
    }

    private static Map<String, Object> parseObject(String json, int[] pos) {
        Map<String, Object> map = new LinkedHashMap<>();
        pos[0]++; // skip {
        skipWhitespace(json, pos);
        if (json.charAt(pos[0]) == '}') { pos[0]++; return map; }
        while (pos[0] < json.length()) {
            skipWhitespace(json, pos);
            String key = parseString(json, pos);
            skipWhitespace(json, pos);
            pos[0]++; // skip :
            Object val = parseValue(json, pos);
            map.put(key, val);
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') pos[0]++;
            else break;
        }
        if (pos[0] < json.length() && json.charAt(pos[0]) == '}') pos[0]++;
        return map;
    }

    private static List<Object> parseArray(String json, int[] pos) {
        List<Object> list = new ArrayList<>();
        pos[0]++; // skip [
        skipWhitespace(json, pos);
        if (json.charAt(pos[0]) == ']') { pos[0]++; return list; }
        while (pos[0] < json.length()) {
            list.add(parseValue(json, pos));
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') pos[0]++;
            else break;
        }
        if (pos[0] < json.length() && json.charAt(pos[0]) == ']') pos[0]++;
        return list;
    }

    private static String parseString(String json, int[] pos) {
        pos[0]++; // skip opening "
        StringBuilder sb = new StringBuilder();
        while (pos[0] < json.length()) {
            char c = json.charAt(pos[0]);
            if (c == '\\') { pos[0]++; sb.append(json.charAt(pos[0])); }
            else if (c == '"') { pos[0]++; return sb.toString(); }
            else sb.append(c);
            pos[0]++;
        }
        return sb.toString();
    }

    private static Object parseNumber(String json, int[] pos) {
        int start = pos[0];
        boolean isFloat = false;
        while (pos[0] < json.length()) {
            char c = json.charAt(pos[0]);
            if (c == '.' || c == 'e' || c == 'E') isFloat = true;
            if (Character.isDigit(c) || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') pos[0]++;
            else break;
        }
        String num = json.substring(start, pos[0]);
        if (isFloat) return Double.parseDouble(num);
        long v = Long.parseLong(num);
        if (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) return (int) v;
        return v;
    }

    private static Boolean parseBoolean(String json, int[] pos) {
        if (json.startsWith("true", pos[0])) { pos[0] += 4; return true; }
        if (json.startsWith("false", pos[0])) { pos[0] += 5; return false; }
        return false;
    }

    private static void skipWhitespace(String json, int[] pos) {
        while (pos[0] < json.length() && Character.isWhitespace(json.charAt(pos[0]))) pos[0]++;
    }
}
