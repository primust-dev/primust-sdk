/**
 * Primust Manifest Registry — In-memory manifest storage.
 *
 * Manifests are registered by content hash (SHA-256 of canonical content
 * without manifest_id and signature). Registration is idempotent:
 * same content → same manifest_id, created=false.
 */
import type { CheckManifest } from '@primust/runtime-core';
export interface ManifestRegistrationResult {
    manifest_id: string;
    created: boolean;
}
export declare class ManifestRegistry {
    private manifests;
    /**
     * Register a manifest. Idempotent by content hash.
     *
     * The manifest_id is the SHA-256 hash of the canonical content
     * (excluding manifest_id and signature fields).
     */
    registerManifest(manifest: CheckManifest): ManifestRegistrationResult;
    /**
     * Get a manifest by manifest_id.
     */
    getManifest(manifestId: string): CheckManifest | undefined;
    /**
     * Get just the manifest hash for a given manifest_id.
     */
    getManifestHash(manifestId: string): string | undefined;
    /**
     * Compute the content hash of a manifest (SHA-256 of canonical content
     * without manifest_id and signature).
     */
    private computeContentHash;
}
//# sourceMappingURL=manifest_registry.d.ts.map