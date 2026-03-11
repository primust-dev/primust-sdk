import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonical } from './canonical.js';

// Load golden vectors
const vectorsPath = resolve(__dirname, '../../../schemas/golden/canonical_vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

describe('canonical', () => {
  describe('golden vectors', () => {
    for (const vec of vectors.vectors) {
      it(`${vec.id}: ${vec.description}`, () => {
        expect(canonical(vec.input)).toBe(vec.expected);
      });
    }
  });

  describe('hash vectors', () => {
    it('produces correct canonical form for hash input', () => {
      const vec = vectors.hash_vectors[0];
      expect(canonical(vec.input)).toBe(vec.canonical);
    });
  });

  describe('invalid vectors — non-JSON-native types must throw', () => {
    it('reject-date-object: Date throws TypeError', () => {
      expect(() => canonical({ ts: new Date() })).toThrow(TypeError);
    });

    it('reject-bytes: Uint8Array throws TypeError', () => {
      expect(() => canonical({ data: new Uint8Array([1, 2, 3]) })).toThrow(TypeError);
    });

    it('reject-undefined-function: function throws TypeError', () => {
      expect(() => canonical({ fn: () => {} })).toThrow(TypeError);
    });

    it('reject-nan: NaN throws TypeError', () => {
      expect(() => canonical({ val: NaN })).toThrow(TypeError);
    });

    it('reject-infinity: Infinity throws TypeError', () => {
      expect(() => canonical({ val: Infinity })).toThrow(TypeError);
    });

    it('reject-negative-infinity: -Infinity throws TypeError', () => {
      expect(() => canonical({ val: -Infinity })).toThrow(TypeError);
    });

    it('reject-symbol: Symbol throws TypeError', () => {
      expect(() => canonical({ val: Symbol('test') })).toThrow(TypeError);
    });

    it('reject-bigint: BigInt throws TypeError', () => {
      expect(() => canonical({ val: BigInt(42) })).toThrow(TypeError);
    });
  });

  describe('edge cases', () => {
    it('undefined object properties are skipped', () => {
      expect(canonical({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
    });

    it('recursive sorting is not top-level-only (Q1 quarantine)', () => {
      // This is the exact pattern that Q1 quarantines:
      // Object.keys().sort() only sorts top-level
      const input = { outer: { z: 1, a: 2 } };
      const result = canonical(input);
      expect(result).toBe('{"outer":{"a":2,"z":1}}');
      // Verify it's NOT the broken top-level-only version
      expect(result).not.toBe('{"outer":{"z":1,"a":2}}');
    });
  });
});
