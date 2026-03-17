package com.primust.sdk;

import java.util.Collections;
import java.util.Map;

/**
 * Input to Run.record() or Pipeline.record().
 * Use RecordInput.builder() to construct.
 *
 * <pre>
 * run.record(
 *     RecordInput.builder()
 *         .check("coverage_verification")
 *         .manifestId("sha256:abc...")
 *         .input(data.getBytes())
 *         .checkResult(CheckResult.PASS)
 *         .details(Map.of("claim_id", "CLM-001"))
 *         .visibility("opaque")
 *         .build()
 * );
 * </pre>
 */
public final class RecordInput {

    private final String check;
    private final String manifestId;
    private final byte[] input;
    private final byte[] output;
    private final CheckResult checkResult;
    private final Map<String, Object> details;
    private final String visibility;

    private RecordInput(Builder b) {
        if (b.check == null) throw new IllegalArgumentException("check is required");
        if (b.manifestId == null) throw new IllegalArgumentException("manifestId is required");
        if (b.input == null) throw new IllegalArgumentException("input is required");
        if (b.checkResult == null) throw new IllegalArgumentException("checkResult is required");
        this.check = b.check;
        this.manifestId = b.manifestId;
        this.input = b.input;
        this.output = b.output;
        this.checkResult = b.checkResult;
        this.details = b.details != null ? Collections.unmodifiableMap(b.details) : Collections.emptyMap();
        this.visibility = b.visibility != null ? b.visibility : "opaque";
    }

    public String check() { return check; }
    public String manifestId() { return manifestId; }
    public byte[] input() { return input; }
    public byte[] output() { return output; }
    public CheckResult checkResult() { return checkResult; }
    public Map<String, Object> details() { return details; }
    public String visibility() { return visibility; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String check;
        private String manifestId;
        private byte[] input;
        private byte[] output;
        private CheckResult checkResult;
        private Map<String, Object> details;
        private String visibility;

        public Builder check(String check) { this.check = check; return this; }
        public Builder manifestId(String manifestId) { this.manifestId = manifestId; return this; }
        public Builder input(byte[] input) { this.input = input; return this; }
        public Builder output(byte[] output) { this.output = output; return this; }
        public Builder checkResult(CheckResult checkResult) { this.checkResult = checkResult; return this; }
        public Builder checkResult(String checkResult) {
            this.checkResult = CheckResult.valueOf(checkResult.toUpperCase());
            return this;
        }
        public Builder details(Map<String, Object> details) { this.details = details; return this; }
        public Builder visibility(String visibility) { this.visibility = visibility; return this; }
        public Builder visibility(VisibilityMode visibility) { this.visibility = visibility.value(); return this; }

        public RecordInput build() { return new RecordInput(this); }
    }
}
