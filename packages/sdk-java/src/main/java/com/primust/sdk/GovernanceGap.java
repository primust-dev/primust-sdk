package com.primust.sdk;

/**
 * A governance gap recorded in the VPEC.
 * Gap types: check_missing, check_failed, check_timing_suspect,
 * sequence_gap, system_unavailable, policy_config_drift.
 */
public final class GovernanceGap {

    private final String gapId;
    private final String gapType;
    private final String severity;
    private final String check;
    private final Integer sequence;
    private final String timestamp;

    public GovernanceGap(String gapId, String gapType, String severity,
                         String check, Integer sequence, String timestamp) {
        this.gapId = gapId;
        this.gapType = gapType;
        this.severity = severity;
        this.check = check;
        this.sequence = sequence;
        this.timestamp = timestamp;
    }

    public String gapId() { return gapId; }
    public String gapType() { return gapType; }
    public String severity() { return severity; }
    public String check() { return check; }
    public Integer sequence() { return sequence; }
    public String timestamp() { return timestamp; }
}
