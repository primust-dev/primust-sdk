package com.primust.cedar;

import com.primust.core.CanonicalJson;
import com.primust.core.Commitment;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PrimustCedarTest {

    @Test
    void surfaceDeclaration() {
        var decl = SurfaceDeclaration.DECLARATION;
        assertEquals("policy_engine", decl.get("surface_type"));
        assertEquals("mathematical", decl.get("proof_ceiling"));
        assertEquals("deterministic_rule", decl.get("stage_type"));
        assertEquals("instrumentation", decl.get("observation_mode"));
        assertEquals("AWS Cedar", decl.get("engine"));
    }

    @Test
    void inputCommitmentDeterministic() {
        // Cedar-style input: principal, action, resource, context
        var input = new LinkedHashMap<String, Object>();
        input.put("principal", "User::\"alice\"");
        input.put("action", "Action::\"read\"");
        input.put("resource", "Document::\"report-1\"");
        input.put("context", Map.of("ip", "10.0.0.1"));

        String json1 = CanonicalJson.canonical(input);
        String json2 = CanonicalJson.canonical(input);
        assertEquals(json1, json2);

        var c1 = Commitment.commit(json1.getBytes(StandardCharsets.UTF_8));
        var c2 = Commitment.commit(json2.getBytes(StandardCharsets.UTF_8));
        assertEquals(c1.hash(), c2.hash());
    }

    @Test
    void canonicalSortsCedarInput() {
        // Keys must be sorted regardless of insertion order
        var input = new LinkedHashMap<String, Object>();
        input.put("resource", "r");
        input.put("action", "a");
        input.put("principal", "p");
        input.put("context", Map.of());

        String json = CanonicalJson.canonical(input);
        assertTrue(json.indexOf("\"action\"") < json.indexOf("\"context\""));
        assertTrue(json.indexOf("\"context\"") < json.indexOf("\"principal\""));
        assertTrue(json.indexOf("\"principal\"") < json.indexOf("\"resource\""));
    }

    @Test
    void adapterCreatesWithDefaults() {
        var adapter = new PrimustCedar("key", null, "m1", "wf1", "hash", null);
        var decl = adapter.getSurfaceDeclaration();
        assertEquals("policy_engine", decl.get("surface_type"));
    }
}
