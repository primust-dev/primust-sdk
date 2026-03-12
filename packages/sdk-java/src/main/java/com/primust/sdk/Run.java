package com.primust.sdk;

import com.primust.core.Commitment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A governed process run. Opened by Pipeline.open().
 *
 * <pre>
 * Run run = pipeline.open();
 * RecordResult result = run.record(RecordInput.builder()
 *     .check("aml_screen")
 *     .manifestId("sha256:...")
 *     .input(entityData)
 *     .checkResult(CheckResult.PASS)
 *     .visibility("opaque")
 *     .build());
 * VPEC vpec = run.close();
 * </pre>
 *
 * INVARIANT: Raw input bytes are committed locally via Poseidon2/SHA-256
 * before anything is transmitted. The transport layer never receives raw values.
 */
public class Run {

    private final String runId;
    private final String workflowId;
    private final String orgId;
    private final HttpTransport transport;
    private final boolean testMode;

    private final ReentrantLock lock = new ReentrantLock();
    private boolean closed = false;
    private int sequence = 0;
    private String chainHash = "";
    private final List<String> recordIds = new ArrayList<>();
    private final List<String> proofLevels = new ArrayList<>();

    Run(String runId, String workflowId, String orgId,
        HttpTransport transport, boolean testMode) {
        this.runId = runId;
        this.workflowId = workflowId;
        this.orgId = orgId;
        this.transport = transport;
        this.testMode = testMode;
    }

    /**
     * Record a governance check execution.
     *
     * INVARIANT: input bytes are committed locally before transmission.
     * Neither the raw input nor the raw output are ever sent to api.primust.com.
     */
    public RecordResult record(RecordInput input) {
        lock.lock();
        try {
            if (closed) {
                throw new IllegalStateException("Cannot record on a closed Run.");
            }

            String recordId = "rec_" + UUID.randomUUID().toString().replace("-", "");
            int seq = sequence++;
            String recordedAt = Instant.now().toString();

            // ── LOCAL COMMITMENT — raw input never leaves ──
            Commitment.CommitmentResult inputCommitment = Commitment.commit(input.input());
            String commitmentHash = inputCommitment.hash();
            String algorithm = inputCommitment.algorithm();

            String outputCommitment = null;
            if (input.output() != null) {
                Commitment.CommitmentResult outResult = Commitment.commitOutput(input.output());
                outputCommitment = outResult.hash();
            }
            // ────────────────────────────────────────────────

            // Rolling chain hash
            String chainInput = chainHash + "|" + recordId + "|" + commitmentHash + "|" + seq;
            chainHash = sha256Hex(chainInput);

            String proofLevel = ProofLevel.ATTESTATION.value();

            // Build envelope — ONLY hashes and metadata, never raw values
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("record_id", recordId);
            envelope.put("run_id", runId);
            envelope.put("manifest_id", input.manifestId());
            envelope.put("check", input.check());
            envelope.put("sequence", seq);
            envelope.put("check_result", input.checkResult().value());
            envelope.put("commitment_hash", commitmentHash);
            envelope.put("commitment_algorithm", algorithm);
            envelope.put("commitment_type", input.output() == null ? "input_only" : "input_output");
            envelope.put("proof_level_achieved", proofLevel);
            envelope.put("visibility", input.visibility());
            envelope.put("chain_hash", chainHash);
            envelope.put("recorded_at", recordedAt);
            envelope.put("idempotency_key", "idem_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));

            if (outputCommitment != null) {
                envelope.put("output_commitment", outputCommitment);
            }
            if (!input.details().isEmpty()) {
                envelope.put("details", input.details());
            }

            proofLevels.add(proofLevel);

            // ── TRANSMIT — only the envelope (no raw data) ──
            Map<String, Object> response = transport.postRecord(runId, envelope);
            boolean queued = (response == null);

            if (response != null && response.containsKey("proof_level")) {
                proofLevel = String.valueOf(response.get("proof_level"));
            }

            recordIds.add(recordId);

            return new RecordResult(
                    recordId, commitmentHash, outputCommitment,
                    algorithm, proofLevel, recordedAt, chainHash, queued);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Close the run and request VPEC issuance.
     * After close(), no further records can be added.
     */
    public VPEC close() {
        lock.lock();
        try {
            if (closed) {
                throw new IllegalStateException("Run already closed.");
            }
            closed = true;
        } finally {
            lock.unlock();
        }

        String closedAt = Instant.now().toString();
        String overallProofLevel = weakestLinkProofLevel();

        Map<String, Object> closePayload = new LinkedHashMap<>();
        closePayload.put("run_id", runId);
        closePayload.put("record_ids", recordIds);
        closePayload.put("final_chain_hash", chainHash);
        closePayload.put("closed_at", closedAt);
        closePayload.put("record_count", recordIds.size());

        Map<String, Object> response = transport.postCloseRun(runId, closePayload);

        if (response == null) {
            // API unreachable — return pending VPEC with system_unavailable gap
            return new VPEC(
                    "vpec_pending_" + runId, runId, workflowId, orgId,
                    closedAt, overallProofLevel, recordIds.size(), 0, 0,
                    List.of(new GovernanceGap(
                            "gap_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16),
                            "system_unavailable", "high", null, null, closedAt)),
                    true, "", "", testMode, Map.of("status", "pending", "run_id", runId));
        }

        return parseVpec(response, overallProofLevel, closedAt);
    }

    public String runId() { return runId; }
    public String workflowId() { return workflowId; }
    public String orgId() { return orgId; }

    private String weakestLinkProofLevel() {
        String[] order = {
                ProofLevel.ATTESTATION.value(),
                ProofLevel.WITNESSED.value(),
                ProofLevel.EXECUTION.value(),
                ProofLevel.EXECUTION_ZKML.value(),
                ProofLevel.MATHEMATICAL.value(),
        };
        if (proofLevels.isEmpty()) return ProofLevel.ATTESTATION.value();
        for (String level : order) {
            if (proofLevels.contains(level)) return level;
        }
        return ProofLevel.ATTESTATION.value();
    }

    @SuppressWarnings("unchecked")
    private VPEC parseVpec(Map<String, Object> data, String localProofLevel, String closedAt) {
        String vpecId = String.valueOf(data.getOrDefault("vpec_id", "vpec_" + runId));
        String proofLevel = String.valueOf(data.getOrDefault("proof_level", localProofLevel));
        String issuedAt = String.valueOf(data.getOrDefault("issued_at", closedAt));
        boolean chainIntact = Boolean.TRUE.equals(data.getOrDefault("chain_intact", true));
        String merkleRoot = String.valueOf(data.getOrDefault("merkle_root", ""));
        String signature = String.valueOf(data.getOrDefault("signature", ""));

        Map<String, Object> coverage = data.containsKey("coverage")
                ? (Map<String, Object>) data.get("coverage") : Map.of();
        int total = toInt(coverage.getOrDefault("records_total", data.getOrDefault("total_checks_run", recordIds.size())));
        int passed = toInt(coverage.getOrDefault("records_pass", data.getOrDefault("checks_passed", 0)));
        int failed = toInt(coverage.getOrDefault("records_fail", data.getOrDefault("checks_failed", 0)));

        List<Map<String, Object>> gapsRaw = data.containsKey("gaps")
                ? (List<Map<String, Object>>) data.get("gaps")
                : data.containsKey("governance_gaps")
                ? (List<Map<String, Object>>) data.get("governance_gaps")
                : List.of();
        List<GovernanceGap> gaps = new ArrayList<>();
        for (Map<String, Object> g : gapsRaw) {
            gaps.add(new GovernanceGap(
                    String.valueOf(g.getOrDefault("gap_id", "")),
                    String.valueOf(g.getOrDefault("gap_type", "")),
                    String.valueOf(g.getOrDefault("severity", "")),
                    g.containsKey("check") ? String.valueOf(g.get("check")) : null,
                    g.containsKey("sequence") ? toInt(g.get("sequence")) : null,
                    String.valueOf(g.getOrDefault("timestamp", ""))));
        }

        return new VPEC(vpecId, runId, workflowId, orgId, issuedAt, proofLevel,
                total, passed, failed, gaps, chainIntact, merkleRoot, signature,
                testMode, data);
    }

    private static int toInt(Object o) {
        if (o instanceof Number) return ((Number) o).intValue();
        try { return Integer.parseInt(String.valueOf(o)); } catch (NumberFormatException e) { return 0; }
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
