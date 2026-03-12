package com.primust.core;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import static org.junit.jupiter.api.Assertions.*;

class CanonicalJsonTest {

    @Test
    void simpleObject() {
        // Cross-language vector V5: {"b": 1, "a": 2} → {"a":2,"b":1}
        // Use LinkedHashMap to verify sorting works regardless of insertion order
        var input = new LinkedHashMap<String, Object>();
        input.put("b", 1);
        input.put("a", 2);
        assertEquals("{\"a\":2,\"b\":1}", CanonicalJson.canonical(input));
    }

    @Test
    void nestedObject() {
        // Cross-language vector V6
        var nested = new LinkedHashMap<String, Object>();
        nested.put("b", 2);
        nested.put("a", 1);
        var input = new LinkedHashMap<String, Object>();
        input.put("z", List.of(1, nested));
        input.put("a", "x");
        assertEquals("{\"a\":\"x\",\"z\":[1,{\"a\":1,\"b\":2}]}", CanonicalJson.canonical(input));
    }

    @Test
    void emptyObject() {
        assertEquals("{}", CanonicalJson.canonical(Map.of()));
    }

    @Test
    void arrayPreservesOrder() {
        // Cross-language vector V8: [3, 1, 2] → [3,1,2]
        assertEquals("[3,1,2]", CanonicalJson.canonical(List.of(3, 1, 2)));
    }

    @Test
    void nullValue() {
        assertEquals("null", CanonicalJson.canonical(null));
    }

    @Test
    void booleans() {
        assertEquals("true", CanonicalJson.canonical(true));
        assertEquals("false", CanonicalJson.canonical(false));
    }

    @Test
    void stringValue() {
        assertEquals("\"hello\"", CanonicalJson.canonical("hello"));
    }

    @Test
    void noWhitespace() {
        var input = Map.of("key", List.of(1, 2, Map.of("nested", true)));
        String result = CanonicalJson.canonical(input);
        assertEquals("{\"key\":[1,2,{\"nested\":true}]}", result);
    }

    @Test
    void rejectsNaN() {
        assertThrows(IllegalArgumentException.class, () ->
            CanonicalJson.canonical(Double.NaN));
    }

    @Test
    void rejectsInfinity() {
        assertThrows(IllegalArgumentException.class, () ->
            CanonicalJson.canonical(Double.POSITIVE_INFINITY));
    }
}
