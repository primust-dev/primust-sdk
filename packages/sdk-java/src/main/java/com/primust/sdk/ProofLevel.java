package com.primust.sdk;

/**
 * Proof level achieved for a governance check.
 * Weakest-link rule: overall VPEC level is the lowest across all checks.
 */
public enum ProofLevel {
    MATHEMATICAL("mathematical"),
    VERIFIABLE_INFERENCE("verifiable_inference"),
    EXECUTION("execution"),
    WITNESSED("witnessed"),
    ATTESTATION("attestation");

    private final String value;

    ProofLevel(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /** Weakest-link ordering: attestation < witnessed < execution < verifiable_inference < mathematical. */
    public boolean isWeakerThan(ProofLevel other) {
        return this.ordinal() > other.ordinal();
    }

    @Override
    public String toString() {
        return value;
    }
}
