package com.primust.sdk;

/**
 * Returned by Run.record(). Write commitmentHash to your operational logs
 * for log linkage — connects your logs to the VPEC.
 */
public final class RecordResult {

    private final String recordId;
    private final String commitmentHash;
    private final String outputCommitment;
    private final String commitmentAlgorithm;
    private final String proofLevel;
    private final String recordedAt;
    private final String chainHash;
    private final boolean queued;

    public RecordResult(
            String recordId,
            String commitmentHash,
            String outputCommitment,
            String commitmentAlgorithm,
            String proofLevel,
            String recordedAt,
            String chainHash,
            boolean queued) {
        this.recordId = recordId;
        this.commitmentHash = commitmentHash;
        this.outputCommitment = outputCommitment;
        this.commitmentAlgorithm = commitmentAlgorithm;
        this.proofLevel = proofLevel;
        this.recordedAt = recordedAt;
        this.chainHash = chainHash;
        this.queued = queued;
    }

    public String recordId() { return recordId; }
    /** Log linkage anchor — write to your operational logs alongside transaction ID. */
    public String commitmentHash() { return commitmentHash; }
    public String outputCommitment() { return outputCommitment; }
    public String commitmentAlgorithm() { return commitmentAlgorithm; }
    public String proofLevel() { return proofLevel; }
    public String recordedAt() { return recordedAt; }
    public String chainHash() { return chainHash; }
    /** True if API was unreachable — record queued locally, will flush on reconnect. */
    public boolean queued() { return queued; }
}
