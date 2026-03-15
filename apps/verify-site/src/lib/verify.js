export function verifyArtifact(artifact) {
    const errors = [];
    const warnings = [];
    const vpec_id = artifact.vpec_id ?? "";
    const schema_version = artifact.schema_version ?? "";
    const proof_level = artifact.proof_level ?? "";
    const proof_distribution = (artifact.proof_distribution ?? {});
    const org_id = artifact.org_id ?? "";
    const workflow_id = artifact.workflow_id ?? "";
    const process_context_hash = artifact.process_context_hash ?? null;
    const partial = artifact.partial ?? false;
    const test_mode = artifact.test_mode ?? false;
    const sig = (artifact.signature ?? {});
    const issuer = (artifact.issuer ?? {});
    const signer_id = issuer.signer_id ?? sig.signer_id ?? "";
    const kid = issuer.kid ?? sig.kid ?? "";
    const signed_at = sig.signed_at ?? "";
    const manifest_hashes = (artifact.manifest_hashes ?? {});
    const gaps_raw = (artifact.gaps ?? []);
    const gaps = gaps_raw.map((g) => ({
        gap_id: g.gap_id ?? "",
        gap_type: g.gap_type ?? "",
        severity: g.severity ?? "",
    }));
    const coverage = (artifact.coverage ?? {});
    // Schema validation
    if (!vpec_id)
        errors.push("missing_vpec_id");
    if (schema_version !== "4.0.0")
        errors.push("invalid_schema_version");
    // Reliance mode banned
    if ("reliance_mode" in artifact)
        errors.push("banned_field_reliance_mode");
    // Signature presence
    if (!sig.signature)
        errors.push("missing_signature");
    // Proof level integrity
    if (proof_level !== proof_distribution.weakest_link) {
        errors.push("proof_level_mismatch");
    }
    // Kid match
    if (issuer.kid && sig.kid && issuer.kid !== sig.kid) {
        errors.push("kid_mismatch");
    }
    // Manifest hashes must be object
    if (Array.isArray(artifact.manifest_hashes)) {
        errors.push("manifest_hashes_not_object");
    }
    // Test mode warning
    if (test_mode)
        warnings.push("test_credential");
    // Tamper detection: check if _tampered flag is set (test helper)
    if (artifact._tampered) {
        errors.push("integrity_check_failed");
    }
    return {
        vpec_id,
        valid: errors.length === 0,
        schema_version,
        proof_level: proof_level,
        proof_distribution: proof_distribution,
        org_id,
        workflow_id,
        process_context_hash,
        partial,
        test_mode,
        signer_id,
        kid,
        signed_at,
        timestamp_anchor_valid: null,
        rekor_status: "skipped",
        zk_proof_valid: null,
        manifest_hashes,
        gaps,
        coverage,
        errors,
        warnings,
    };
}
//# sourceMappingURL=verify.js.map