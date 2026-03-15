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
export declare function canonical(value: unknown): string;
//# sourceMappingURL=canonical.d.ts.map