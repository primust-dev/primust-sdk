/**
 * Primust Evidence Pack — Pack Assembly (P8-A)
 *
 * assemblePack(artifacts, period, org_id, signerRecord, privateKey) → EvidencePack
 *
 * Steps:
 *   1. Load/validate each VPEC via P2-A offline verifier
 *   2. Compute Merkle root over artifact commitment_roots (poseidon2)
 *   3. Compute coverage buckets (must sum to 100)
 *   4. Aggregate proof_distribution across all 5 levels
 *   5. Aggregate gaps by severity
 *   6. Build observation_summary
 *   7. Build EvidencePack — no reliance_mode
 *   8. report_hash = SHA256(canonical(pack_without_signature))
 *   9. Sign with artifact_signer
 *  10. Timestamp stub
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { sha256 } from '@noble/hashes/sha256';
import { canonical, sign, buildCommitmentRoot, } from '@primust/artifact-core';
import { verify as verifyArtifact } from '@primust/verifier';
// ── Helpers ──
function hexEncode(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
/**
 * Pre-cache a signer's public key so the verifier can resolve it offline.
 */
function ensureKeyCache(kid, publicKeyB64Url) {
    const cacheDir = join(homedir(), '.primust', 'keys');
    if (!existsSync(cacheDir)) {
        mkdirSync(cacheDir, { recursive: true });
    }
    const safe = kid.replace(/[^a-zA-Z0-9_-]/g, '_');
    const keyPath = join(cacheDir, `${safe}.pem`);
    if (!existsSync(keyPath)) {
        writeFileSync(keyPath, publicKeyB64Url, 'utf-8');
    }
}
const PROOF_LEVELS = [
    'mathematical',
    'verifiable_inference',
    'execution',
    'witnessed',
    'attestation',
];
function scopeToNonProveStatement(scopeType) {
    switch (scopeType) {
        case 'full_workflow':
            return 'All workflow steps were observed via direct instrumentation.';
        case 'orchestration_boundary':
            return 'Actions that bypassed the orchestration boundary are not covered.';
        case 'platform_logged_events':
            return 'Coverage reflects what the platform logged, not all actions.';
        case 'partial_unknown':
            return 'Surface scope is partially unknown. Coverage is a lower bound.';
        default:
            return 'Coverage scope details are not specified.';
    }
}
// ── Main ──
/**
 * Assemble an Evidence Pack from multiple VPEC artifacts.
 *
 * @param artifacts - Array of VPECArtifact objects to include
 * @param periodStart - Period start (ISO 8601)
 * @param periodEnd - Period end (ISO 8601)
 * @param orgId - Organization ID
 * @param signerRecord - Active SignerRecord for signing
 * @param privateKey - Ed25519 private key bytes
 * @param coverageOptions - Coverage bucket percentages (must sum to 100)
 * @returns Signed EvidencePackWithInstructions
 */
export async function assemblePack(artifacts, periodStart, periodEnd, orgId, signerRecord, privateKey, coverageOptions) {
    if (artifacts.length === 0) {
        throw new Error('Cannot assemble Evidence Pack from zero artifacts');
    }
    // Pre-cache the pack signer's public key for offline verification
    ensureKeyCache(signerRecord.kid, signerRecord.public_key_b64url);
    // Step 1: Verify each artifact via P2-A offline verifier
    for (const artifact of artifacts) {
        const result = await verifyArtifact(artifact, { skip_network: true });
        if (!result.valid) {
            throw new Error(`Artifact ${artifact.vpec_id} failed verification: ${result.errors.join(', ')}`);
        }
    }
    // Step 2: Compute Merkle root over artifact commitment_roots
    const commitmentRoots = artifacts
        .map((a) => a.commitment_root)
        .filter((r) => r !== null);
    if (commitmentRoots.length === 0) {
        throw new Error('Evidence Pack requires at least one artifact with a non-null commitment_root');
    }
    const merkleRoot = buildCommitmentRoot(commitmentRoots);
    // Step 3: Validate coverage buckets
    const { coverage_verified_pct, coverage_pending_pct, coverage_ungoverned_pct } = coverageOptions;
    const coverageSum = coverage_verified_pct + coverage_pending_pct + coverage_ungoverned_pct;
    if (Math.round(coverageSum) !== 100) {
        throw new Error(`Coverage buckets must sum to 100, got ${coverageSum} ` +
            `(${coverage_verified_pct} + ${coverage_pending_pct} + ${coverage_ungoverned_pct})`);
    }
    // Step 4: Aggregate proof_distribution across all 5 levels
    const proofDist = {
        mathematical: 0,
        verifiable_inference: 0,
        execution: 0,
        witnessed: 0,
        attestation: 0,
    };
    for (const artifact of artifacts) {
        for (const level of PROOF_LEVELS) {
            proofDist[level] += artifact.proof_distribution[level] ?? 0;
        }
    }
    // Step 5: Aggregate gaps by severity
    const gapSummary = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Informational: 0,
    };
    for (const artifact of artifacts) {
        for (const gap of artifact.gaps) {
            const sev = gap.severity;
            if (sev in gapSummary) {
                gapSummary[sev]++;
            }
        }
    }
    // Step 6: Build observation_summary
    const surfaceMap = new Map();
    for (const artifact of artifacts) {
        for (const surface of artifact.surface_summary) {
            if (!surfaceMap.has(surface.surface_id)) {
                surfaceMap.set(surface.surface_id, {
                    surface_id: surface.surface_id,
                    surface_coverage_statement: surface.surface_coverage_statement,
                });
            }
        }
    }
    const observationSummary = Array.from(surfaceMap.values());
    // Step 7: Build manifest_hashes map (aggregated from all artifacts)
    const aggregatedManifestHashes = {};
    for (const artifact of artifacts) {
        for (const [manifestId, hash] of Object.entries(artifact.manifest_hashes)) {
            aggregatedManifestHashes[manifestId] = hash;
        }
    }
    // Determine scope type for verification instructions
    const primaryScope = artifacts[0]?.surface_summary[0]?.scope_type ?? 'partial_unknown';
    // Step 8: Build pack document
    const packId = `pack_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const packDocument = {
        pack_id: packId,
        org_id: orgId,
        period_start: periodStart,
        period_end: periodEnd,
        artifact_ids: artifacts.map((a) => a.vpec_id),
        merkle_root: merkleRoot,
        proof_distribution: proofDist,
        coverage_verified_pct,
        coverage_pending_pct,
        coverage_ungoverned_pct,
        observation_summary: observationSummary,
        gap_summary: gapSummary,
        manifest_hashes: aggregatedManifestHashes,
        // report_hash placeholder — computed below
        report_hash: '',
        signature: {
            signer_id: signerRecord.signer_id,
            kid: signerRecord.kid,
            algorithm: 'Ed25519',
            signature: '',
            signed_at: now,
        },
        timestamp_anchor: {
            type: 'none',
            tsa: 'none',
            value: null,
        },
        generated_at: now,
        verification_instructions: buildVerificationInstructions(packId, primaryScope, coverage_verified_pct, observationSummary),
    };
    // Step 9: report_hash = SHA256(canonical(pack_without_signature))
    const { signature: _sig, ...packWithoutSignature } = packDocument;
    const reportCanonical = canonical(packWithoutSignature);
    const reportHashBytes = sha256(new TextEncoder().encode(reportCanonical));
    packDocument.report_hash = 'sha256:' + hexEncode(reportHashBytes);
    // Step 10: Sign with artifact_signer
    const { signatureEnvelope } = sign(packDocument, privateKey, signerRecord);
    packDocument.signature = {
        signer_id: signatureEnvelope.signer_id,
        kid: signatureEnvelope.kid,
        algorithm: signatureEnvelope.algorithm,
        signature: signatureEnvelope.signature,
        signed_at: signatureEnvelope.signed_at,
    };
    return packDocument;
}
// ── Dry Run ──
/**
 * Pure function — produces a human-readable dry-run summary.
 * Zero API calls, zero side effects.
 */
export function dryRunOutput(artifactIds, periodStart, periodEnd, coverageVerifiedPct, coveragePendingPct, coverageUngovernedPct, surfaceSummaryLine, totalRecords) {
    const lines = [
        '=== PRIMUST DRY RUN ===',
        '',
        `Period:          ${periodStart} → ${periodEnd}`,
        `Artifacts:       ${artifactIds.length}`,
        `Total records:   ${totalRecords}`,
        '',
        'Artifact IDs:',
        ...artifactIds.map((id) => `  - ${id}`),
        '',
        'Coverage:',
        `  Verified:    ${coverageVerifiedPct}%`,
        `  Pending:     ${coveragePendingPct}%`,
        `  Ungoverned:  ${coverageUngovernedPct}%`,
        '',
        `Surface:         ${surfaceSummaryLine}`,
        '',
        'Raw content:     NONE (privacy invariant — only commitment hashes transit)',
        '',
        '=== End dry run ===',
    ];
    return lines.join('\n');
}
// ── Verification Instructions ──
function buildVerificationInstructions(packId, scopeType, coverageVerifiedPct, observationSummary) {
    const surfaceBasis = observationSummary.length > 0
        ? observationSummary.map((s) => s.surface_coverage_statement).join('; ')
        : 'No observation surfaces registered';
    return {
        cli_command: `primust pack verify ${packId}.json`,
        offline_command: `primust pack verify ${packId}.json --trust-root <key.pem>`,
        trust_root_url: 'https://keys.primust.com/jwks',
        what_this_proves: `${coverageVerifiedPct}% of required governance checks were executed and passed within the reporting period.`,
        what_this_does_not_prove: scopeToNonProveStatement(scopeType),
        coverage_basis_explanation: surfaceBasis,
    };
}
//# sourceMappingURL=pack_assembler.js.map