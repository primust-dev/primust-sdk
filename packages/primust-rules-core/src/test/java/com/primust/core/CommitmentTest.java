package com.primust.core;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.LinkedHashMap;
import static org.junit.jupiter.api.Assertions.*;

class CommitmentTest {

    @Test
    void commitPoseidon2Empty() {
        var r = Commitment.commit(new byte[]{}, "poseidon2");
        assertEquals(
            "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1",
            r.hash()
        );
        assertEquals("poseidon2", r.algorithm());
    }

    @Test
    void commitPoseidon2Hello() {
        var r = Commitment.commit("hello".getBytes(), "poseidon2");
        assertEquals(
            "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960",
            r.hash()
        );
    }

    @Test
    void commitSha256Hello() {
        var r = Commitment.commit("hello".getBytes(), "sha256");
        assertEquals(
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            r.hash()
        );
        assertEquals("sha256", r.algorithm());
    }

    @Test
    void commitOutputDefaultSha256() {
        var r = Commitment.commitOutput("test output".getBytes());
        assertEquals("sha256", r.algorithm());
        assertTrue(r.hash().startsWith("sha256:"));
    }

    @Test
    void commitDeterministic() {
        var r1 = Commitment.commit("deterministic".getBytes());
        var r2 = Commitment.commit("deterministic".getBytes());
        assertEquals(r1.hash(), r2.hash());
        // Default algorithm is sha256
        assertEquals("sha256", r1.algorithm());
    }

    @Test
    void canonicalThenCommit() {
        // Cross-language vector V9
        var input = new LinkedHashMap<String, Object>();
        input.put("entity", "Acme Corp");
        input.put("type", "company");
        String json = CanonicalJson.canonical(input);
        assertEquals("{\"entity\":\"Acme Corp\",\"type\":\"company\"}", json);

        var r = Commitment.commit(json.getBytes(), "poseidon2");
        assertEquals(
            "poseidon2:2b685b61654c85ab77d25d28d64bf007777cc0c8a15cdcc06ea1d16f362d8d87",
            r.hash()
        );
    }

    @Test
    void buildCommitmentRootDefaultSha256TwoHashes() {
        String h1 = "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1";
        String h2 = "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960";
        // Default path: SHA-256 intermediate nodes
        String result = Commitment.buildCommitmentRoot(List.of(h1, h2));
        assertEquals(
            "sha256:f38d3e31305f6071a1042bc7bedfdd0dfc87f96e6d1d42aa5c7257ffb83090c3",
            result
        );
    }

    @Test
    void buildCommitmentRootPoseidon2ExplicitTwoHashes() {
        String h1 = "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1";
        String h2 = "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960";
        String result = Commitment.buildCommitmentRoot(List.of(h1, h2), "poseidon2");
        assertEquals(
            "poseidon2:0986c2eb74fa0774e9d04991e4e3853796d264478409cd94900b86c875732ef0",
            result
        );
    }

    @Test
    void buildCommitmentRootPoseidon2ExplicitThreeHashes() {
        String h1 = "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1";
        String h2 = "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960";
        String h3 = "poseidon2:287bf2eb6b6e174667ce2927eaefe1b151b758a8db683a43e41fb4f44c074b23";
        String result = Commitment.buildCommitmentRoot(List.of(h1, h2, h3), "poseidon2");
        assertEquals(
            "poseidon2:276d577a0c7471c9656aa4b3fb08eda71e5c66079085bc5993fa854ef06dfdce",
            result
        );
    }

    @Test
    void buildCommitmentRootEmpty() {
        assertNull(Commitment.buildCommitmentRoot(List.of()));
    }

    @Test
    void buildCommitmentRootSingle() {
        String h = "poseidon2:abc123";
        assertEquals(h, Commitment.buildCommitmentRoot(List.of(h)));
    }

    @Test
    void selectProofLevel() {
        assertEquals("mathematical", ProofLevel.selectProofLevel("deterministic_rule"));
        assertEquals("mathematical", ProofLevel.selectProofLevel("policy_engine"));
        assertEquals("execution", ProofLevel.selectProofLevel("ml_model"));
        assertEquals("verifiable_inference", ProofLevel.selectProofLevel("zkml_model"));
        assertEquals("witnessed", ProofLevel.selectProofLevel("witnessed"));
    }

    @Test
    void selectProofLevelUnknown() {
        assertThrows(IllegalArgumentException.class, () ->
            ProofLevel.selectProofLevel("unknown"));
    }
}
