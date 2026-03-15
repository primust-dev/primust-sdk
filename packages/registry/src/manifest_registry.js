/**
 * Primust Manifest Registry — In-memory manifest storage.
 *
 * Manifests are registered by content hash (SHA-256 of canonical content
 * without manifest_id and signature). Registration is idempotent:
 * same content → same manifest_id, created=false.
 */
import { sha256 } from '@noble/hashes/sha256';
import { canonical } from '@primust/artifact-core';
// ── Registry ──
export class ManifestRegistry {
    manifests = new Map(); // manifest_id → CheckManifest
    /**
     * Register a manifest. Idempotent by content hash.
     *
     * The manifest_id is the SHA-256 hash of the canonical content
     * (excluding manifest_id and signature fields).
     */
    registerManifest(manifest) {
        const contentHash = this.computeContentHash(manifest);
        const manifestId = `sha256:${contentHash}`;
        if (this.manifests.has(manifestId)) {
            return { manifest_id: manifestId, created: false };
        }
        this.manifests.set(manifestId, manifest);
        return { manifest_id: manifestId, created: true };
    }
    /**
     * Get a manifest by manifest_id.
     */
    getManifest(manifestId) {
        return this.manifests.get(manifestId);
    }
    /**
     * Get just the manifest hash for a given manifest_id.
     */
    getManifestHash(manifestId) {
        const manifest = this.manifests.get(manifestId);
        return manifest?.manifest_hash;
    }
    /**
     * Compute the content hash of a manifest (SHA-256 of canonical content
     * without manifest_id and signature).
     */
    computeContentHash(manifest) {
        // Build content object without manifest_id and signature
        const content = Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== 'manifest_id' && k !== 'signature'));
        const canonicalStr = canonical(content);
        const hashBytes = sha256(new TextEncoder().encode(canonicalStr));
        return Array.from(hashBytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
    }
}
//# sourceMappingURL=manifest_registry.js.map