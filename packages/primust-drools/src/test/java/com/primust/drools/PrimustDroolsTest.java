package com.primust.drools;

import com.primust.core.CanonicalJson;
import com.primust.core.Commitment;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PrimustDroolsTest {

    @Test
    void surfaceDeclaration() {
        var decl = SurfaceDeclaration.DECLARATION;
        assertEquals("policy_engine", decl.get("surface_type"));
        assertEquals("mathematical", decl.get("proof_ceiling"));
        assertEquals("Drools (KIE)", decl.get("engine"));
    }

    @Test
    void factsCommitmentDeterministic() {
        var fact1 = new LinkedHashMap<String, Object>();
        fact1.put("type", "LoanApplication");
        fact1.put("amount", 50000);
        fact1.put("applicant_score", 720);

        var fact2 = new LinkedHashMap<String, Object>();
        fact2.put("type", "CreditPolicy");
        fact2.put("min_score", 680);

        List<Map<String, Object>> facts = List.of(fact1, fact2);
        String json1 = CanonicalJson.canonical(facts);
        String json2 = CanonicalJson.canonical(facts);
        assertEquals(json1, json2);

        var c1 = Commitment.commit(json1.getBytes(StandardCharsets.UTF_8));
        var c2 = Commitment.commit(json2.getBytes(StandardCharsets.UTF_8));
        assertEquals(c1.hash(), c2.hash());
    }

    @Test
    void ruleNamesCommitted() {
        // Rule names should be committable
        List<String> ruleNames = List.of("MinScoreCheck", "MaxDTICheck", "CollateralRequirement");
        String json = CanonicalJson.canonical(ruleNames);
        var commitment = Commitment.commitOutput(json.getBytes(StandardCharsets.UTF_8));
        assertEquals("poseidon2", commitment.algorithm());
        assertTrue(commitment.hash().startsWith("poseidon2:"));
    }

    @Test
    void adapterCreatesWithDefaults() {
        var adapter = new PrimustDrools("key", null, "m1", "wf1", null);
        var decl = adapter.getSurfaceDeclaration();
        assertEquals("policy_engine", decl.get("surface_type"));
    }
}
