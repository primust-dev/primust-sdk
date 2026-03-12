package com.primust.core;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Poseidon2 hash function over BN254 scalar field.
 * <p>
 * Parameters: t=4, d=5 (S-box x^5), 4+56+4 rounds.
 * Ported from primust_artifact_core (Python reference implementation).
 */
public final class Poseidon2 {

    private static final BigInteger P = Constants.BN254_P;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final int RATE = 3;
    private static final int T = 4;

    private Poseidon2() {}

    // ── S-box ──

    /** x^5 mod p */
    static BigInteger sbox(BigInteger x) {
        BigInteger x2 = x.multiply(x).mod(P);
        BigInteger x4 = x2.multiply(x2).mod(P);
        return x4.multiply(x).mod(P);
    }

    // ── Matrix multiplies ──

    static BigInteger[] matmulExternal4(BigInteger[] s) {
        BigInteger t0 = s[0].add(s[1]).mod(P);
        BigInteger t1 = s[2].add(s[3]).mod(P);
        BigInteger t2 = s[1].add(s[1]).add(t1).mod(P);
        BigInteger t3 = s[3].add(s[3]).add(t0).mod(P);
        BigInteger t4 = t1.add(t1).mod(P);
        t4 = t4.add(t4).add(t3).mod(P);
        BigInteger t5 = t0.add(t0).mod(P);
        t5 = t5.add(t5).add(t2).mod(P);
        BigInteger t6 = t3.add(t5).mod(P);
        BigInteger t7 = t2.add(t4).mod(P);
        return new BigInteger[]{t6, t5, t7, t4};
    }

    static BigInteger[] matmulInternal4(BigInteger[] s) {
        BigInteger total = s[0].add(s[1]).add(s[2]).add(s[3]).mod(P);
        BigInteger[] out = new BigInteger[T];
        for (int i = 0; i < T; i++) {
            out[i] = Constants.MAT_DIAG4_M_1[i].multiply(s[i]).add(total).mod(P);
        }
        return out;
    }

    // ── Permutation ──

    /** Full Poseidon2 permutation for BN254, t=4. */
    public static BigInteger[] permute(BigInteger[] state) {
        BigInteger[] s = new BigInteger[T];
        for (int i = 0; i < T; i++) {
            s[i] = state[i];
        }

        // Initial external matrix
        s = matmulExternal4(s);

        // 4 full beginning rounds
        for (int r = 0; r < 4; r++) {
            BigInteger[] rc = Constants.RC_FULL_BEGIN[r];
            for (int i = 0; i < T; i++) {
                s[i] = s[i].add(rc[i]).mod(P);
            }
            for (int i = 0; i < T; i++) {
                s[i] = sbox(s[i]);
            }
            s = matmulExternal4(s);
        }

        // 56 partial rounds
        for (int r = 0; r < 56; r++) {
            s[0] = s[0].add(Constants.RC_PARTIAL[r]).mod(P);
            s[0] = sbox(s[0]);
            s = matmulInternal4(s);
        }

        // 4 full ending rounds
        for (int r = 0; r < 4; r++) {
            BigInteger[] rc = Constants.RC_FULL_END[r];
            for (int i = 0; i < T; i++) {
                s[i] = s[i].add(rc[i]).mod(P);
            }
            for (int i = 0; i < T; i++) {
                s[i] = sbox(s[i]);
            }
            s = matmulExternal4(s);
        }

        return s;
    }

    // ── Sponge ──

    private static final int MODE_ABSORB = 0;
    private static final int MODE_SQUEEZE = 1;

    /**
     * Poseidon2 sponge construction with rate=3, capacity=1, t=4.
     */
    public static class Sponge {
        private BigInteger[] state = new BigInteger[T];
        private BigInteger[] cache = new BigInteger[RATE];
        private int cacheSize = 0;
        private int mode = MODE_ABSORB;

        public Sponge(BigInteger domainIV) {
            for (int i = 0; i < T; i++) state[i] = BigInteger.ZERO;
            state[3] = domainIV;
            for (int i = 0; i < RATE; i++) cache[i] = BigInteger.ZERO;
        }

        private BigInteger[] performDuplex() {
            for (int i = cacheSize; i < RATE; i++) {
                cache[i] = BigInteger.ZERO;
            }
            for (int i = 0; i < RATE; i++) {
                state[i] = state[i].add(cache[i]).mod(P);
            }
            state = permute(state);
            BigInteger[] out = new BigInteger[RATE];
            for (int i = 0; i < RATE; i++) {
                out[i] = state[i];
            }
            return out;
        }

        public void absorb(BigInteger value) {
            if (mode == MODE_ABSORB && cacheSize == RATE) {
                performDuplex();
                cache[0] = value;
                cacheSize = 1;
            } else if (mode == MODE_ABSORB && cacheSize < RATE) {
                cache[cacheSize] = value;
                cacheSize++;
            } else if (mode == MODE_SQUEEZE) {
                cache[0] = value;
                cacheSize = 1;
                mode = MODE_ABSORB;
            }
        }

        public BigInteger squeeze() {
            if (mode == MODE_SQUEEZE && cacheSize == 0) {
                mode = MODE_ABSORB;
                cacheSize = 0;
            }
            if (mode == MODE_ABSORB) {
                BigInteger[] newOutput = performDuplex();
                mode = MODE_SQUEEZE;
                System.arraycopy(newOutput, 0, cache, 0, RATE);
                cacheSize = RATE;
            }
            BigInteger result = cache[0];
            for (int i = 1; i < cacheSize; i++) {
                cache[i - 1] = cache[i];
            }
            cacheSize--;
            cache[cacheSize] = BigInteger.ZERO;
            return result;
        }
    }

    // ── Hash ──

    /**
     * Hash a list of field elements using Poseidon2 sponge (fixed-length).
     */
    public static BigInteger hash(List<BigInteger> inputs) {
        int outLen = 1;
        BigInteger iv = BigInteger.valueOf(inputs.size())
            .shiftLeft(64)
            .add(BigInteger.valueOf(outLen - 1));
        Sponge sponge = new Sponge(iv);
        for (BigInteger v : inputs) {
            sponge.absorb(v);
        }
        return sponge.squeeze();
    }

    // ── Byte conversion ──

    /**
     * Convert bytes to BN254 field elements (31-byte chunks, big-endian).
     */
    public static List<BigInteger> bytesToFieldElements(byte[] data) {
        if (data.length == 0) {
            return List.of(BigInteger.ZERO);
        }
        var elements = new java.util.ArrayList<BigInteger>();
        int chunkSize = 31;
        for (int i = 0; i < data.length; i += chunkSize) {
            int end = Math.min(i + chunkSize, data.length);
            byte[] chunk = Arrays.copyOfRange(data, i, end);
            // big-endian unsigned
            BigInteger value = new BigInteger(1, chunk);
            elements.add(value.mod(P));
        }
        return elements;
    }

    /**
     * Poseidon2 hash over arbitrary bytes, matching TS/Python commitment implementations.
     */
    public static String poseidon2Bytes(byte[] data) {
        List<BigInteger> elements = bytesToFieldElements(data);
        BigInteger state = BigInteger.ZERO;
        for (int i = 0; i < elements.size(); i += 2) {
            BigInteger left = elements.get(i);
            BigInteger right = (i + 1 < elements.size()) ? elements.get(i + 1) : BigInteger.ZERO;
            BigInteger sum = state.add(left).mod(P);
            state = hash(List.of(sum, right));
        }
        String hex = state.toString(16);
        while (hex.length() < 64) {
            hex = "0" + hex;
        }
        return "poseidon2:" + hex;
    }
}
