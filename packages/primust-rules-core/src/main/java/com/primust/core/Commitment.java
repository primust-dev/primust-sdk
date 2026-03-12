package com.primust.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Commitment layer for Primust policy engine adapters.
 * <p>
 * PRIVACY INVARIANT: Raw content NEVER leaves the customer environment.
 * Only the commitment hash transits to Primust API.
 */
public final class Commitment {

    private Commitment() {}

    /**
     * Result of a commitment computation.
     */
    public record CommitmentResult(String hash, String algorithm) {}

    /**
     * Compute a commitment hash over input bytes.
     *
     * @param data      raw content bytes (NEVER transmitted)
     * @param algorithm "poseidon2" (default) or "sha256"
     */
    public static CommitmentResult commit(byte[] data, String algorithm) {
        if ("sha256".equals(algorithm)) {
            return new CommitmentResult(sha256Hex(data), "sha256");
        }
        return new CommitmentResult(Poseidon2.poseidon2Bytes(data), "poseidon2");
    }

    /** Commit with default poseidon2 algorithm. */
    public static CommitmentResult commit(byte[] data) {
        return commit(data, "poseidon2");
    }

    /** Commitment for check output. Always uses poseidon2. */
    public static CommitmentResult commitOutput(byte[] data) {
        return new CommitmentResult(Poseidon2.poseidon2Bytes(data), "poseidon2");
    }

    /**
     * Build a Merkle root over an array of commitment hashes.
     *
     * @return poseidon2 Merkle root, or null for empty array.
     *         Single hash returns unchanged.
     */
    public static String buildCommitmentRoot(List<String> hashes) {
        if (hashes.isEmpty()) return null;
        if (hashes.size() == 1) return hashes.get(0);

        var layer = new java.util.ArrayList<BigInteger>();
        for (String h : hashes) {
            layer.add(parseHashToField(h));
        }

        while (layer.size() > 1) {
            var next = new java.util.ArrayList<BigInteger>();
            for (int i = 0; i < layer.size(); i += 2) {
                BigInteger left = layer.get(i);
                BigInteger right = (i + 1 < layer.size()) ? layer.get(i + 1) : layer.get(i);
                next.add(Poseidon2.hash(List.of(left, right)));
            }
            layer = next;
        }

        String hex = layer.get(0).toString(16);
        while (hex.length() < 64) hex = "0" + hex;
        return "poseidon2:" + hex;
    }

    // ── Helpers ──

    private static BigInteger parseHashToField(String hash) {
        int colonIdx = hash.indexOf(':');
        if (colonIdx == -1) throw new IllegalArgumentException("Invalid hash format: " + hash);
        String hex = hash.substring(colonIdx + 1);
        return new BigInteger(hex, 16).mod(Constants.BN254_P);
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder("sha256:");
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
