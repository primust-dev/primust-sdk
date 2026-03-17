package com.primust.sdk;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Verifiable Process Execution Credential.
 *
 * Returned by Run.close(). Portable, offline-verifiable.
 * Verify at verify.primust.com or with primust-verify CLI.
 */
public final class VPEC {

    private final String vpecId;
    private final String runId;
    private final String workflowId;
    private final String orgId;
    private final String issuedAt;
    private final String proofLevel;
    private final int totalChecksRun;
    private final int checksPassed;
    private final int checksFailed;
    private final List<GovernanceGap> governanceGaps;
    private final boolean chainIntact;
    private final String merkleRoot;
    private final String signature;
    private final boolean testMode;
    private final Map<String, Object> raw;

    public VPEC(String vpecId, String runId, String workflowId, String orgId,
                String issuedAt, String proofLevel, int totalChecksRun,
                int checksPassed, int checksFailed,
                List<GovernanceGap> governanceGaps, boolean chainIntact,
                String merkleRoot, String signature, boolean testMode,
                Map<String, Object> raw) {
        this.vpecId = vpecId;
        this.runId = runId;
        this.workflowId = workflowId;
        this.orgId = orgId;
        this.issuedAt = issuedAt;
        this.proofLevel = proofLevel;
        this.totalChecksRun = totalChecksRun;
        this.checksPassed = checksPassed;
        this.checksFailed = checksFailed;
        this.governanceGaps = governanceGaps != null ? Collections.unmodifiableList(governanceGaps) : List.of();
        this.chainIntact = chainIntact;
        this.merkleRoot = merkleRoot;
        this.signature = signature;
        this.testMode = testMode;
        this.raw = raw != null ? Collections.unmodifiableMap(raw) : Map.of();
    }

    public String vpecId() { return vpecId; }
    public String runId() { return runId; }
    public String workflowId() { return workflowId; }
    public String orgId() { return orgId; }
    public String issuedAt() { return issuedAt; }
    /** Weakest-link proof level across all checks in this run. */
    public String proofLevel() { return proofLevel; }
    public int totalChecksRun() { return totalChecksRun; }
    public int checksPassed() { return checksPassed; }
    public int checksFailed() { return checksFailed; }
    public List<GovernanceGap> governanceGaps() { return governanceGaps; }
    public boolean chainIntact() { return chainIntact; }
    public String merkleRoot() { return merkleRoot; }
    public String signature() { return signature; }
    public boolean testMode() { return testMode; }
    /** Full JSON for offline verification. */
    public Map<String, Object> toMap() { return raw; }
    public int gapsCount() { return governanceGaps.size(); }
    /** True if chain is intact AND zero governance gaps. */
    public boolean isClean() { return chainIntact && governanceGaps.isEmpty(); }
}
