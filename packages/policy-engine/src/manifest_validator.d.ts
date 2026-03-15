/**
 * Primust Policy Engine — Manifest Validation + Proof Ceiling
 *
 * Pure functions, no database dependency.
 *
 * PROOF CEILING: weakest stage.proof_level across all stages.
 * Hierarchy: mathematical > verifiable_inference > execution > witnessed > attestation
 *
 * MANIFEST HASH: SHA256(canonical(manifest_without_manifest_id_and_signature))
 * manifest_id = manifest_hash (content-addressed identity)
 */
import type { ProofLevel } from '@primust/artifact-core';
import type { CheckManifest, ManifestBenchmark, CheckExecutionRecord } from '@primust/runtime-core';
import type { ValidationError } from '@primust/runtime-core';
/**
 * Proof level hierarchy: lower index = stronger.
 * mathematical (0) > verifiable_inference (1) > execution (2) > witnessed (3) > attestation (4)
 */
export declare const PROOF_LEVEL_HIERARCHY: readonly ProofLevel[];
/**
 * Compute the proof ceiling for a manifest: the weakest stage.proof_level.
 * This is the best proof level the manifest can achieve.
 */
export declare function computeProofCeiling(manifest: CheckManifest): ProofLevel;
/**
 * Compute the manifest hash: SHA256(canonical(manifest without manifest_id and signature)).
 * Returns `sha256:` prefixed hex string.
 */
export declare function computeManifestHash(manifest: CheckManifest): string;
/**
 * Validate a CheckManifest. Returns validation errors.
 *
 * Delegates to runtime-core validateManifestStage() per stage, then adds
 * whole-manifest checks: proof ceiling consistency, stage numbering.
 */
export declare function validateManifest(manifest: CheckManifest): ValidationError[];
/**
 * Bind a benchmark to a manifest. Returns a new manifest with the benchmark attached.
 */
export declare function bindBenchmark(manifest: CheckManifest, benchmark: ManifestBenchmark): CheckManifest;
/**
 * Validate required fields on a CheckExecutionRecord.
 * Delegates to runtime-core validateCheckExecutionRecord().
 */
export declare function validateRecordFields(record: CheckExecutionRecord): ValidationError[];
//# sourceMappingURL=manifest_validator.d.ts.map