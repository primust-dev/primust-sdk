export { canonical } from './canonical.js';
export { generateKeyPair, sign, verify, rotateKey, toBase64Url, fromBase64Url } from './signing.js';
export { commit, commitOutput, buildCommitmentRoot, selectProofLevel, ZK_IS_BLOCKING, } from './commitment.js';
export type { CommitmentResult } from './commitment.js';
export { validateArtifact } from './validate-artifact.js';
export type { ValidationError, ValidationResult } from './validate-artifact.js';
export type { SignerRecord, SignatureEnvelope, KeyStatus, RevocationReason, SignerType, } from './types.js';
export type { VPECArtifact, ProofLevel, SurfaceEntry, ProofDistribution, Coverage, GapEntry, ZkProof, ArtifactIssuer, ArtifactSignature, TimestampAnchor, TransparencyLog, PendingFlags, GapType, GapSeverity, SurfaceType, ObservationMode, ScopeType, PolicyBasis, ArtifactState, CommitmentAlgorithm, Prover, ProverSystem, TsaProvider, OrgRegion, } from './types/artifact.js';
//# sourceMappingURL=index.d.ts.map