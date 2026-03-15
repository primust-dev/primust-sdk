/**
 * Public key cache — filesystem cache at ~/.primust/keys/{kid}.pem
 *
 * Keys are immutable by kid. Once cached, never re-fetched.
 * On cache miss with network failure: throws "key_unavailable".
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
const CACHE_DIR = join(homedir(), '.primust', 'keys');
function ensureCacheDir() {
    if (!existsSync(CACHE_DIR)) {
        mkdirSync(CACHE_DIR, { recursive: true });
    }
}
function cachePath(kid) {
    // Sanitize kid to prevent path traversal
    const safe = kid.replace(/[^a-zA-Z0-9_-]/g, '_');
    return join(CACHE_DIR, `${safe}.pem`);
}
/**
 * Resolve a public key PEM for the given kid.
 *
 * Resolution order:
 * 1. If trustRoot is provided, read from that path (bypass cache/fetch)
 * 2. Check filesystem cache (~/.primust/keys/{kid}.pem)
 * 3. Fetch from publicKeyUrl, write to cache
 * 4. On network failure with cache miss: throw "key_unavailable"
 */
export async function getKey(kid, publicKeyUrl, trustRoot) {
    // Option 1: custom trust root — read directly
    if (trustRoot) {
        try {
            return readFileSync(trustRoot, 'utf-8').trim();
        }
        catch {
            throw new Error(`key_unavailable: cannot read trust root at ${trustRoot}`);
        }
    }
    // Option 2: check cache
    ensureCacheDir();
    const cached = cachePath(kid);
    if (existsSync(cached)) {
        return readFileSync(cached, 'utf-8').trim();
    }
    // Option 3: fetch from URL
    try {
        const response = await fetch(publicKeyUrl);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const pem = (await response.text()).trim();
        writeFileSync(cached, pem, 'utf-8');
        return pem;
    }
    catch {
        throw new Error(`key_unavailable: cannot fetch public key for kid ${kid} from ${publicKeyUrl}`);
    }
}
//# sourceMappingURL=key-cache.js.map