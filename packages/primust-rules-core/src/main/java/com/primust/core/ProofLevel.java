package com.primust.core;

import java.util.Map;

/**
 * Proof level selection for stage types.
 * <p>
 * Mapping:
 * <ul>
 *   <li>deterministic_rule → mathematical</li>
 *   <li>policy_engine → mathematical</li>
 *   <li>hardware_attested → mathematical</li>
 *   <li>zkml_model → execution_zkml</li>
 *   <li>ml_model → execution</li>
 *   <li>statistical_test → execution</li>
 *   <li>custom_code → execution</li>
 *   <li>open_source_ml → execution</li>
 *   <li>human_review → witnessed</li>
 *   <li>byollm → attestation</li>
 * </ul>
 */
public final class ProofLevel {

    private ProofLevel() {}

    private static final Map<String, String> MAPPING = new java.util.HashMap<>(Map.of(
        "deterministic_rule", "mathematical",
        "policy_engine", "mathematical",
        "hardware_attested", "mathematical",
        "zkml_model", "execution_zkml",
        "ml_model", "execution",
        "statistical_test", "execution",
        "custom_code", "execution",
        "human_review", "witnessed"
    ));
    static {
        MAPPING.put("byollm", "attestation");
        MAPPING.put("open_source_ml", "execution");
    }

    /**
     * Select the proof level for a given stage type.
     *
     * @throws IllegalArgumentException for unknown stage types
     */
    public static String selectProofLevel(String stageType) {
        String result = MAPPING.get(stageType);
        if (result == null) {
            throw new IllegalArgumentException("Unknown stage type: " + stageType);
        }
        return result;
    }
}
