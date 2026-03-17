package com.primust.sdk;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.time.Instant;

/**
 * Primust governance pipeline.
 *
 * <pre>
 * Pipeline p = Primust.builder()
 *     .apiKey("pk_live_...")
 *     .workflowId("claims-adjudication-v1")
 *     .build();
 *
 * Run run = p.open();
 * run.record(RecordInput.builder()
 *     .check("coverage_verification")
 *     .manifestId("sha256:...")
 *     .input(claimData)
 *     .checkResult(CheckResult.PASS)
 *     .visibility("opaque")
 *     .build());
 * VPEC vpec = run.close();
 * </pre>
 *
 * Raw input committed locally via Poseidon2 — never transmitted.
 */
public class Pipeline {

    private final String apiKey;
    private final String workflowId;
    private final String baseUrl;
    private final String surfaceId;
    private final boolean testMode;
    private final HttpTransport transport;
    private String orgId;

    Pipeline(String apiKey, String workflowId, String baseUrl, String surfaceId) {
        this.apiKey = apiKey;
        this.workflowId = workflowId;
        this.baseUrl = baseUrl;
        this.surfaceId = surfaceId;
        this.testMode = apiKey.startsWith("pk_test_") || apiKey.startsWith("pk_sb_");
        this.transport = new HttpTransport(apiKey, baseUrl);
    }

    /**
     * Open a new governed process run.
     * Returns a Run. Call run.record() for each governance check.
     * Close with run.close() to issue the VPEC.
     */
    public Run open() {
        return open(null);
    }

    /**
     * Open a new governed process run with a policy pack.
     */
    public Run open(String policyPackId) {
        String runId = "run_" + UUID.randomUUID().toString().replace("-", "");
        String openedAt = Instant.now().toString();

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("run_id", runId);
        payload.put("workflow_id", workflowId);
        payload.put("environment", testMode ? "test" : "production");
        payload.put("opened_at", openedAt);
        if (policyPackId != null) payload.put("policy_pack_id", policyPackId);
        if (surfaceId != null) payload.put("surface_id", surfaceId);

        Map<String, Object> response = transport.postOpenRun(payload);
        String serverRunId = runId;
        if (response != null) {
            serverRunId = String.valueOf(response.getOrDefault("run_id", runId));
            orgId = String.valueOf(response.getOrDefault("org_id", "unknown"));
        }

        return new Run(serverRunId, workflowId, orgId != null ? orgId : "unknown",
                transport, testMode);
    }

    /**
     * Register a check manifest. Call once per manifest version.
     * Returns ManifestRegistration with content-addressed manifest_id.
     */
    public ManifestRegistration registerCheck(Map<String, Object> manifest) {
        Map<String, Object> response = transport.postManifest(manifest);
        if (response == null) {
            // Queued — return stub
            return new ManifestRegistration(
                    "auto:" + manifest.getOrDefault("name", "unknown"),
                    String.valueOf(manifest.getOrDefault("name", "")),
                    Instant.now().toString());
        }
        return new ManifestRegistration(
                String.valueOf(response.getOrDefault("manifest_id", "")),
                String.valueOf(manifest.getOrDefault("name", "")),
                String.valueOf(response.getOrDefault("registered_at", "")));
    }

    /**
     * Convenience: record directly on a new implicit run (one-shot pattern).
     * Opens a run, records, and closes in one call.
     */
    public RecordResult record(RecordInput input) {
        Run run = open();
        RecordResult result = run.record(input);
        run.close();
        return result;
    }

    public String workflowId() { return workflowId; }
    public boolean testMode() { return testMode; }
}
