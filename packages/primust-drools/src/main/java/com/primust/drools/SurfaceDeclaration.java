package com.primust.drools;

import java.util.Map;

/**
 * Surface declaration for the Drools adapter.
 */
public final class SurfaceDeclaration {

    private SurfaceDeclaration() {}

    public static final Map<String, Object> DECLARATION = Map.ofEntries(
        Map.entry("surface_type", "policy_engine"),
        Map.entry("stage_type", "deterministic_rule"),
        Map.entry("observation_mode", "instrumentation"),
        Map.entry("scope_type", "per_evaluation"),
        Map.entry("proof_ceiling", "mathematical"),
        Map.entry("adapter", "primust-drools"),
        Map.entry("engine", "Drools (KIE)")
    );
}
