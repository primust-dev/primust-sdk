package com.primust.odm;

import com.primust.core.CanonicalJson;
import com.primust.core.Commitment;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PrimustODMTest {

    @Test
    void surfaceDeclaration() {
        var decl = SurfaceDeclaration.DECLARATION;
        assertEquals("policy_engine", decl.get("surface_type"));
        assertEquals("deterministic_rule", decl.get("stage_type"));
        assertEquals("mathematical", decl.get("proof_ceiling"));
        assertEquals("IBM Operational Decision Manager", decl.get("engine"));
    }

    @Test
    void rulesetParamsCommitmentDeterministic() {
        var params = new LinkedHashMap<String, Object>();
        params.put("applicant_score", 720);
        params.put("loan_amount", 250000);
        params.put("ltv_ratio", 0.8);

        String json1 = CanonicalJson.canonical(params);
        String json2 = CanonicalJson.canonical(params);
        assertEquals(json1, json2);

        var c1 = Commitment.commit(json1.getBytes(StandardCharsets.UTF_8));
        var c2 = Commitment.commit(json2.getBytes(StandardCharsets.UTF_8));
        assertEquals(c1.hash(), c2.hash());
    }

    @Test
    void generateStagesFromRules() {
        var adapter = new PrimustODM("key", null, "m1", "wf1", "CreditApp", "Underwriting", null);
        List<String> rulesFired = List.of(
            "MinCreditScoreCheck",
            "MaxDTICheck",
            "CollateralRequirement",
            "FraudIndicatorCheck"
        );

        var stages = adapter.generateStagesFromRules(rulesFired);
        assertEquals(4, stages.size());

        // Each stage should be policy_engine type with mathematical proof
        for (int i = 0; i < stages.size(); i++) {
            var stage = stages.get(i);
            assertEquals(i + 1, stage.get("stage"));
            assertEquals(rulesFired.get(i), stage.get("name"));
            assertEquals("policy_engine", stage.get("type"));
            assertEquals("mathematical", stage.get("proof_level"));
        }
    }

    @Test
    void rulesFiredCommitment() {
        // getRulesFired() output should be committable
        List<String> rulesFired = List.of("Rule1", "Rule2", "Rule3");
        String json = CanonicalJson.canonical(rulesFired);
        var commitment = Commitment.commitOutput(json.getBytes(StandardCharsets.UTF_8));
        assertEquals("poseidon2", commitment.algorithm());
        assertTrue(commitment.hash().startsWith("poseidon2:"));
    }

    @Test
    void adapterCreatesWithDefaults() {
        var adapter = new PrimustODM("key", null, "m1", "wf1", "app", "ruleset", null);
        var decl = adapter.getSurfaceDeclaration();
        assertEquals("policy_engine", decl.get("surface_type"));
    }
}
