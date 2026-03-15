/**
 * Primust Canonical JSON Serialization
 *
 * Produces deterministic JSON output with recursively sorted keys
 * and no whitespace. Two structurally identical objects always produce
 * the same string regardless of key insertion order.
 *
 * Rules:
 * - Object keys sorted lexicographically at every nesting depth
 * - Array element order preserved (never sorted)
 * - No whitespace (no spaces, no newlines, no indentation)
 * - Only JSON-native types accepted: string, number, boolean, null, object, array
 * - Non-JSON-native types (Date, Uint8Array, function, undefined, NaN, Infinity) → TypeError
 *
 * Reference: schemas/golden/canonical_vectors.json
 * Quarantine: Q1 (top-level-only sort), Q6 (no-sort), Q8 (default=str coercion)
 */
/**
 * Recursively serialize a value to canonical JSON.
 *
 * @throws TypeError if the value contains non-JSON-native types
 */
export function canonical(value) {
    return serializeValue(value);
}
function serializeValue(value) {
    if (value === null) {
        return 'null';
    }
    switch (typeof value) {
        case 'string':
            return JSON.stringify(value);
        case 'number':
            if (!Number.isFinite(value)) {
                throw new TypeError(`canonical: cannot serialize ${value} (NaN/Infinity are not valid JSON)`);
            }
            return JSON.stringify(value);
        case 'boolean':
            return value ? 'true' : 'false';
        case 'object':
            if (Array.isArray(value)) {
                return serializeArray(value);
            }
            if (value instanceof Date) {
                throw new TypeError('canonical: Date objects must be converted to ISO 8601 strings before serialization');
            }
            if (value instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(value))) {
                throw new TypeError('canonical: byte arrays must be base64url-encoded before serialization');
            }
            return serializeObject(value);
        case 'undefined':
            throw new TypeError('canonical: undefined is not valid JSON');
        case 'function':
            throw new TypeError('canonical: functions are not valid JSON');
        case 'symbol':
            throw new TypeError('canonical: symbols are not valid JSON');
        case 'bigint':
            throw new TypeError('canonical: BigInt must be converted to string or number before serialization');
        default:
            throw new TypeError(`canonical: unsupported type ${typeof value}`);
    }
}
function serializeObject(obj) {
    const keys = Object.keys(obj).sort();
    const pairs = [];
    for (const key of keys) {
        const val = obj[key];
        if (val === undefined) {
            // Skip undefined values (matches JSON.stringify behavior)
            continue;
        }
        pairs.push(`${JSON.stringify(key)}:${serializeValue(val)}`);
    }
    return `{${pairs.join(',')}}`;
}
function serializeArray(arr) {
    const elements = [];
    for (const item of arr) {
        elements.push(serializeValue(item));
    }
    return `[${elements.join(',')}]`;
}
//# sourceMappingURL=canonical.js.map