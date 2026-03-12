package com.primust.cedar;

import java.util.Map;

/**
 * Surface declaration for the Cedar adapter.
 */
public final class SurfaceDeclaration {

    private SurfaceDeclaration() {}

    public static final Map<String, Object> DECLARATION = Map.of(
        "surface_type", "policy_engine",
        "observation_mode", "instrumentation",
        "scope_type", "per_evaluation",
        "proof_ceiling", "mathematical",
        "adapter", "primust-cedar",
        "engine", "AWS Cedar"
    );
}
