package com.primust.core;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Canonical JSON serialization with recursively sorted keys and no whitespace.
 * <p>
 * Rules:
 * <ul>
 *   <li>Object keys sorted lexicographically at every nesting depth</li>
 *   <li>Array element order preserved (never sorted)</li>
 *   <li>No whitespace</li>
 *   <li>Only JSON-native types: String, Number, Boolean, null, Map, List</li>
 * </ul>
 */
public final class CanonicalJson {

    private CanonicalJson() {}

    /**
     * Serialize a value to canonical JSON.
     *
     * @throws IllegalArgumentException if the value contains unsupported types
     */
    public static String canonical(Object value) {
        StringBuilder sb = new StringBuilder();
        serialize(value, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void serialize(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
            return;
        }

        if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
            return;
        }

        if (value instanceof Integer || value instanceof Long) {
            sb.append(value);
            return;
        }

        if (value instanceof Double d) {
            if (d.isNaN() || d.isInfinite()) {
                throw new IllegalArgumentException(
                    "canonical: cannot serialize " + d + " (NaN/Infinity are not valid JSON)");
            }
            // Use Number formatting that matches JSON spec
            if (d == Math.floor(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) {
                sb.append(String.valueOf(d.longValue()));
            } else {
                sb.append(d);
            }
            return;
        }

        if (value instanceof Float f) {
            serialize(f.doubleValue(), sb);
            return;
        }

        if (value instanceof String s) {
            serializeString(s, sb);
            return;
        }

        if (value instanceof Map<?, ?> map) {
            serializeObject((Map<String, Object>) map, sb);
            return;
        }

        if (value instanceof List<?> list) {
            serializeArray((List<Object>) list, sb);
            return;
        }

        throw new IllegalArgumentException(
            "canonical: unsupported type " + value.getClass().getName());
    }

    private static void serializeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static void serializeObject(Map<String, Object> map, StringBuilder sb) {
        // TreeMap sorts keys lexicographically
        TreeMap<String, Object> sorted = new TreeMap<>(map);
        sb.append('{');
        boolean first = true;
        for (var entry : sorted.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            serializeString(entry.getKey(), sb);
            sb.append(':');
            serialize(entry.getValue(), sb);
        }
        sb.append('}');
    }

    private static void serializeArray(List<Object> list, StringBuilder sb) {
        sb.append('[');
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(',');
            serialize(list.get(i), sb);
        }
        sb.append(']');
    }
}
