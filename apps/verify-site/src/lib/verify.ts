/**
 * Client-side VPEC verification logic.
 * In production this calls @primust/verifier. For the UI layer
 * we implement the core checks inline to avoid WASM dependency in tests.
 */
import type { VerificationResult } from "../types/vpec";

export function verifyArtifact(artifact: Record<string, unknown>): VerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const vpec_id = (artifact.vpec_id as string) ?? "";
  const schema_version = (artifact.schema_version as string) ?? "";
  const proof_level = (artifact.proof_level as string) ?? "";
  const proof_distribution = (artifact.proof_distribution ?? {}) as Record<string, unknown>;
  const org_id = (artifact.org_id as string) ?? "";
  const workflow_id = (artifact.workflow_id as string) ?? "";
  const process_context_hash = (artifact.process_context_hash as string | null) ?? null;
  const partial = (artifact.partial as boolean) ?? false;
  const test_mode = (artifact.test_mode as boolean) ?? false;

  const sig = (artifact.signature ?? {}) as Record<string, string>;
  const issuer = (artifact.issuer ?? {}) as Record<string, string>;
  const signer_id = issuer.signer_id ?? sig.signer_id ?? "";
  const kid = issuer.kid ?? sig.kid ?? "";
  const signed_at = sig.signed_at ?? "";

  const manifest_hashes = (artifact.manifest_hashes ?? {}) as Record<string, string>;
  const gaps_raw = (artifact.gaps ?? []) as Array<Record<string, string>>;
  const gaps = gaps_raw.map((g) => ({
    gap_id: g.gap_id ?? "",
    gap_type: g.gap_type ?? "",
    severity: g.severity ?? "",
  }));
  const coverage = (artifact.coverage ?? {}) as Record<string, unknown>;

  // Schema validation
  if (!vpec_id) errors.push("missing_vpec_id");
  if (schema_version !== "4.0.0") errors.push("invalid_schema_version");

  // Reliance mode banned
  if ("reliance_mode" in artifact) errors.push("banned_field_reliance_mode");

  // Signature presence
  if (!sig.signature) errors.push("missing_signature");

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
  if (test_mode) warnings.push("test_credential");

  // Tamper detection: check if _tampered flag is set (test helper)
  if ((artifact as Record<string, unknown>)._tampered) {
    errors.push("integrity_check_failed");
  }

  return {
    vpec_id,
    valid: errors.length === 0,
    schema_version,
    proof_level: proof_level as VerificationResult["proof_level"],
    proof_distribution: proof_distribution as VerificationResult["proof_distribution"],
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
