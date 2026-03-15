/**
 * Public key cache — filesystem cache at ~/.primust/keys/{kid}.pem
 *
 * Keys are immutable by kid. Once cached, never re-fetched.
 * On cache miss with network failure: throws "key_unavailable".
 */
/**
 * Resolve a public key PEM for the given kid.
 *
 * Resolution order:
 * 1. If trustRoot is provided, read from that path (bypass cache/fetch)
 * 2. Check filesystem cache (~/.primust/keys/{kid}.pem)
 * 3. Fetch from publicKeyUrl, write to cache
 * 4. On network failure with cache miss: throw "key_unavailable"
 */
export declare function getKey(kid: string, publicKeyUrl: string, trustRoot?: string): Promise<string>;
//# sourceMappingURL=key-cache.d.ts.map