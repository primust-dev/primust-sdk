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
import { sha256 } from '@noble/hashes/sha256';
import { canonical } from '@primust/artifact-core';
import { validateManifestStage, validateCheckExecutionRecord, } from '@primust/runtime-core';
// ── Constants ──
/**
 * Proof level hierarchy: lower index = stronger.
 * mathematical (0) > verifiable_inference (1) > execution (2) > witnessed (3) > attestation (4)
 */
export const PROOF_LEVEL_HIERARCHY = [
    'mathematical',
    'verifiable_inference',
    'execution',
    'witnessed',
    'attestation',
];
// ── Helpers ──
function proofLevelRank(level) {
    const idx = PROOF_LEVEL_HIERARCHY.indexOf(level);
    if (idx === -1)
        throw new Error(`Unknown proof level: ${level}`);
    return idx;
}
function hexEncode(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
// ── Proof Ceiling ──
/**
 * Compute the proof ceiling for a manifest: the weakest stage.proof_level.
 * This is the best proof level the manifest can achieve.
 */
export function computeProofCeiling(manifest) {
    if (!manifest.stages || manifest.stages.length === 0) {
        return 'attestation';
    }
    let weakest = manifest.stages[0].proof_level;
    for (const stage of manifest.stages) {
        if (proofLevelRank(stage.proof_level) > proofLevelRank(weakest)) {
            weakest = stage.proof_level;
        }
    }
    return weakest;
}
// ── Manifest Hash ──
/**
 * Compute the manifest hash: SHA256(canonical(manifest without manifest_id and signature)).
 * Returns `sha256:` prefixed hex string.
 */
export function computeManifestHash(manifest) {
    const content = Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== 'manifest_id' && k !== 'manifest_hash' && k !== 'signature'));
    const canonicalStr = canonical(content);
    const hashBytes = sha256(new TextEncoder().encode(canonicalStr));
    return 'sha256:' + hexEncode(hashBytes);
}
// ── Manifest Validation ──
/**
 * Validate a CheckManifest. Returns validation errors.
 *
 * Delegates to runtime-core validateManifestStage() per stage, then adds
 * whole-manifest checks: proof ceiling consistency, stage numbering.
 */
export function validateManifest(manifest) {
    const errors = [];
    // 1. Must have at least one stage
    if (!manifest.stages || manifest.stages.length === 0) {
        errors.push({
            code: 'manifest_no_stages',
            message: 'Manifest must have at least one stage',
        });
        return errors;
    }
    // 2. Validate each stage (delegates to runtime-core)
    for (const stage of manifest.stages) {
        errors.push(...validateManifestStage(stage));
    }
    // 3. Proof ceiling consistency
    const computedCeiling = computeProofCeiling(manifest);
    if (proofLevelRank(manifest.supported_proof_level) < proofLevelRank(computedCeiling)) {
        errors.push({
            code: 'proof_level_above_ceiling',
            message: `supported_proof_level (${manifest.supported_proof_level}) is above ` +
                `the computed proof ceiling (${computedCeiling})`,
        });
    }
    if (manifest.supported_proof_level !== computedCeiling) {
        errors.push({
            code: 'proof_ceiling_mismatch',
            message: `supported_proof_level (${manifest.supported_proof_level}) does not match ` +
                `computed proof ceiling (${computedCeiling})`,
        });
    }
    // 4. evaluation_window_seconds required for per_window scope
    if (manifest.evaluation_scope === 'per_window' &&
        (manifest.evaluation_window_seconds === null || manifest.evaluation_window_seconds === undefined)) {
        errors.push({
            code: 'window_seconds_required',
            message: 'evaluation_window_seconds is required when evaluation_scope = per_window',
        });
    }
    return errors;
}
// ── Benchmark Binding ──
/**
 * Bind a benchmark to a manifest. Returns a new manifest with the benchmark attached.
 */
export function bindBenchmark(manifest, benchmark) {
    return { ...manifest, benchmark };
}
// ── Record Field Validation ──
/**
 * Validate required fields on a CheckExecutionRecord.
 * Delegates to runtime-core validateCheckExecutionRecord().
 */
export function validateRecordFields(record) {
    return validateCheckExecutionRecord(record);
}
//# sourceMappingURL=manifest_validator.js.map