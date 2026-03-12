package com.primust.odm;

import java.util.Map;

/**
 * Surface declaration for the IBM ODM adapter.
 */
public final class SurfaceDeclaration {

    private SurfaceDeclaration() {}

    public static final Map<String, Object> DECLARATION = Map.of(
        "surface_type", "policy_engine",
        "observation_mode", "instrumentation",
        "scope_type", "per_evaluation",
        "proof_ceiling", "mathematical",
        "adapter", "primust-odm",
        "engine", "IBM Operational Decision Manager"
    );
}
