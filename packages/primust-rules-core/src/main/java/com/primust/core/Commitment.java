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
     * Resolve the commitment algorithm from env var or default.
     * Default is "sha256". Poseidon2 is opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2
     * until an audited implementation (e.g. Barretenberg) is validated.
     */
    public static String resolveAlgorithm() {
        String alg = System.getenv("PRIMUST_COMMITMENT_ALGORITHM");
        if ("poseidon2".equals(alg)) return "poseidon2";
        return "sha256";
    }

    /**
     * Compute a commitment hash over input bytes.
     *
     * @param data      raw content bytes (NEVER transmitted)
     * @param algorithm "sha256" (default) or "poseidon2"
     */
    public static CommitmentResult commit(byte[] data, String algorithm) {
        if ("poseidon2".equals(algorithm)) {
            return new CommitmentResult(Poseidon2.poseidon2Bytes(data), "poseidon2");
        }
        return new CommitmentResult(sha256Hex(data), "sha256");
    }

    /** Commit with resolved algorithm (env var or sha256 default). */
    public static CommitmentResult commit(byte[] data) {
        return commit(data, resolveAlgorithm());
    }

    /** Commitment for check output. Uses resolved algorithm. */
    public static CommitmentResult commitOutput(byte[] data) {
        return commit(data, resolveAlgorithm());
    }

    /**
     * Build a Merkle root over an array of commitment hashes.
     * Uses the resolved algorithm (SHA-256 default, Poseidon2 opt-in) for intermediate nodes.
     *
     * @return Merkle root, or null for empty array. Single hash returns unchanged.
     */
    public static String buildCommitmentRoot(List<String> hashes) {
        return buildCommitmentRoot(hashes, resolveAlgorithm());
    }

    /**
     * Build a Merkle root with an explicit algorithm for intermediate nodes.
     */
    public static String buildCommitmentRoot(List<String> hashes, String algorithm) {
        if (hashes.isEmpty()) return null;
        if (hashes.size() == 1) return hashes.get(0);

        if ("poseidon2".equals(algorithm)) {
            return buildPoseidon2MerkleRoot(hashes);
        }
        return buildSha256MerkleRoot(hashes);
    }

    private static String buildPoseidon2MerkleRoot(List<String> hashes) {
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

    private static String buildSha256MerkleRoot(List<String> hashes) {
        var layer = new java.util.ArrayList<byte[]>();
        for (String h : hashes) {
            layer.add(parseHashToRawBytes(h));
        }

        while (layer.size() > 1) {
            var next = new java.util.ArrayList<byte[]>();
            for (int i = 0; i < layer.size(); i += 2) {
                byte[] left = layer.get(i);
                byte[] right = (i + 1 < layer.size()) ? layer.get(i + 1) : layer.get(i);
                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(left);
                    md.update(right);
                    next.add(md.digest());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("SHA-256 not available", e);
                }
            }
            layer = next;
        }

        StringBuilder sb = new StringBuilder("sha256:");
        for (byte b : layer.get(0)) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ── Helpers ──

    private static byte[] parseHashToRawBytes(String hash) {
        int colonIdx = hash.indexOf(':');
        if (colonIdx == -1) throw new IllegalArgumentException("Invalid hash format: " + hash);
        String hex = hash.substring(colonIdx + 1);
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

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
