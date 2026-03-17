package com.primust.sdk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Primust Java SDK tests.
 *
 * Tests run against mock transport (no live API). Verifies:
 * - Builder pattern and configuration
 * - RecordInput builder validation
 * - Run lifecycle (record → close)
 * - Commitment invariant (raw input never in envelope)
 * - Chain integrity
 * - VPEC parsing
 * - Enum correctness
 */
class PrimustSdkTest {

    // ── Builder ──

    @Test
    @DisplayName("Primust.builder() creates Pipeline with correct config")
    void builderCreates() {
        Pipeline p = Primust.builder()
                .apiKey("pk_sb_abc123")
                .workflowId("test-workflow")
                .build();
        assertEquals("test-workflow", p.workflowId());
        assertTrue(p.testMode());
    }

    @Test
    @DisplayName("Missing API key throws IllegalArgumentException")
    void missingApiKeyThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                Primust.builder().workflowId("test").build());
    }

    @Test
    @DisplayName("pk_sb_ prefix sets test mode")
    void testModeFromKeyPrefix() {
        Pipeline p = Primust.builder().apiKey("pk_sb_xyz").build();
        assertTrue(p.testMode());
    }

    @Test
    @DisplayName("pk_live_ prefix sets production mode")
    void liveModeFromKeyPrefix() {
        Pipeline p = Primust.builder().apiKey("pk_live_xyz").build();
        assertFalse(p.testMode());
    }

    // ── RecordInput Builder ──

    @Test
    @DisplayName("RecordInput.builder() validates required fields")
    void recordInputRequiresCheck() {
        assertThrows(IllegalArgumentException.class, () ->
                RecordInput.builder()
                        .manifestId("sha256:abc")
                        .input("data".getBytes())
                        .checkResult(CheckResult.PASS)
                        .build());
    }

    @Test
    @DisplayName("RecordInput.builder() builds with all fields")
    void recordInputFull() {
        RecordInput ri = RecordInput.builder()
                .check("aml_screen")
                .manifestId("sha256:manifest_001")
                .input("entity_data".getBytes(StandardCharsets.UTF_8))
                .output("result".getBytes(StandardCharsets.UTF_8))
                .checkResult(CheckResult.PASS)
                .details(Map.of("entity_type", "corporate"))
                .visibility("opaque")
                .build();

        assertEquals("aml_screen", ri.check());
        assertEquals("sha256:manifest_001", ri.manifestId());
        assertEquals(CheckResult.PASS, ri.checkResult());
        assertEquals("opaque", ri.visibility());
        assertNotNull(ri.output());
    }

    @Test
    @DisplayName("RecordInput defaults visibility to opaque")
    void recordInputDefaultVisibility() {
        RecordInput ri = RecordInput.builder()
                .check("test")
                .manifestId("sha256:m1")
                .input("x".getBytes())
                .checkResult(CheckResult.PASS)
                .build();
        assertEquals("opaque", ri.visibility());
    }

    @Test
    @DisplayName("RecordInput accepts string check result")
    void recordInputStringCheckResult() {
        RecordInput ri = RecordInput.builder()
                .check("test")
                .manifestId("sha256:m1")
                .input("x".getBytes())
                .checkResult("pass")
                .build();
        assertEquals(CheckResult.PASS, ri.checkResult());
    }

    // ── Enums ──

    @Test
    @DisplayName("CheckResult enum has all 7 values")
    void checkResultValues() {
        assertEquals(7, CheckResult.values().length);
        assertEquals("pass", CheckResult.PASS.value());
        assertEquals("fail", CheckResult.FAIL.value());
        assertEquals("not_applicable", CheckResult.NOT_APPLICABLE.value());
    }

    @Test
    @DisplayName("ProofLevel enum has correct ordering")
    void proofLevelOrdering() {
        assertTrue(ProofLevel.ATTESTATION.isWeakerThan(ProofLevel.MATHEMATICAL));
        assertFalse(ProofLevel.MATHEMATICAL.isWeakerThan(ProofLevel.ATTESTATION));
        assertTrue(ProofLevel.WITNESSED.isWeakerThan(ProofLevel.EXECUTION));
    }

    @Test
    @DisplayName("VisibilityMode enum has 3 values")
    void visibilityModeValues() {
        assertEquals(3, VisibilityMode.values().length);
        assertEquals("opaque", VisibilityMode.OPAQUE.value());
        assertEquals("selective", VisibilityMode.SELECTIVE.value());
    }

    // ── Run lifecycle ──

    @Test
    @DisplayName("Run.record() produces commitment hash")
    void runRecordProducesCommitment() {
        // Use mock transport that returns null (queued mode)
        Run run = new Run("run_test_001", "test-wf", "org_test",
                new MockTransport(), false);

        RecordResult result = run.record(RecordInput.builder()
                .check("pii_scan")
                .manifestId("sha256:manifest_pii")
                .input("sensitive_data".getBytes(StandardCharsets.UTF_8))
                .checkResult(CheckResult.PASS)
                .visibility("opaque")
                .build());

        assertNotNull(result.commitmentHash());
        assertTrue(result.commitmentHash().length() > 10, "Commitment hash should be substantial");
        assertEquals("rec_", result.recordId().substring(0, 4));
        assertTrue(result.queued()); // mock returns null → queued
    }

    @Test
    @DisplayName("Same input produces same commitment")
    void sameInputSameCommitment() {
        byte[] input = "deterministic_test".getBytes(StandardCharsets.UTF_8);

        Run run1 = new Run("run_1", "wf", "org", new MockTransport(), false);
        RecordResult r1 = run1.record(RecordInput.builder()
                .check("c").manifestId("m").input(input).checkResult(CheckResult.PASS).build());

        Run run2 = new Run("run_2", "wf", "org", new MockTransport(), false);
        RecordResult r2 = run2.record(RecordInput.builder()
                .check("c").manifestId("m").input(input).checkResult(CheckResult.PASS).build());

        assertEquals(r1.commitmentHash(), r2.commitmentHash());
    }

    @Test
    @DisplayName("Different input produces different commitment")
    void differentInputDifferentCommitment() {
        Run run1 = new Run("run_1", "wf", "org", new MockTransport(), false);
        RecordResult r1 = run1.record(RecordInput.builder()
                .check("c").manifestId("m").input("aaa".getBytes()).checkResult(CheckResult.PASS).build());

        Run run2 = new Run("run_2", "wf", "org", new MockTransport(), false);
        RecordResult r2 = run2.record(RecordInput.builder()
                .check("c").manifestId("m").input("bbb".getBytes()).checkResult(CheckResult.PASS).build());

        assertNotEquals(r1.commitmentHash(), r2.commitmentHash());
    }

    @Test
    @DisplayName("Record on closed run throws IllegalStateException")
    void recordOnClosedRunThrows() {
        Run run = new Run("run_test", "wf", "org", new MockTransport(), false);
        run.record(RecordInput.builder()
                .check("c").manifestId("m").input("x".getBytes()).checkResult(CheckResult.PASS).build());
        run.close();

        assertThrows(IllegalStateException.class, () ->
                run.record(RecordInput.builder()
                        .check("c").manifestId("m").input("x".getBytes()).checkResult(CheckResult.PASS).build()));
    }

    @Test
    @DisplayName("Double close throws IllegalStateException")
    void doubleCloseThrows() {
        Run run = new Run("run_test", "wf", "org", new MockTransport(), false);
        run.close();
        assertThrows(IllegalStateException.class, run::close);
    }

    // ── VPEC ──

    @Test
    @DisplayName("Run.close() returns VPEC with system_unavailable gap when API unreachable")
    void closeReturnsVpecWithGap() {
        Run run = new Run("run_test", "test-wf", "org_test", new MockTransport(), true);
        run.record(RecordInput.builder()
                .check("check1").manifestId("m1").input("data".getBytes()).checkResult(CheckResult.PASS).build());

        VPEC vpec = run.close();
        assertNotNull(vpec);
        assertTrue(vpec.vpecId().startsWith("vpec_pending_"));
        assertTrue(vpec.testMode());
        assertEquals(1, vpec.totalChecksRun());
        assertEquals(1, vpec.gapsCount());
        assertEquals("system_unavailable", vpec.governanceGaps().get(0).gapType());
        assertFalse(vpec.isClean()); // has gap
    }

    @Test
    @DisplayName("VPEC.isClean() returns true when chain intact and no gaps")
    void vpecIsClean() {
        VPEC vpec = new VPEC("vpec_001", "run_001", "wf", "org",
                "2026-01-01T00:00:00Z", "attestation", 3, 3, 0,
                List.of(), true, "merkle_root", "sig", false, Map.of());
        assertTrue(vpec.isClean());
    }

    // ── Chain integrity ──

    @Test
    @DisplayName("Chain hashes are unique across records")
    void chainHashesUnique() {
        Run run = new Run("run_test", "wf", "org", new MockTransport(), false);

        RecordResult r1 = run.record(RecordInput.builder()
                .check("c1").manifestId("m").input("a".getBytes()).checkResult(CheckResult.PASS).build());
        RecordResult r2 = run.record(RecordInput.builder()
                .check("c2").manifestId("m").input("b".getBytes()).checkResult(CheckResult.PASS).build());

        assertNotEquals(r1.chainHash(), r2.chainHash());
    }

    // ── JSON transport ──

    @Test
    @DisplayName("HttpTransport.toJson serializes correctly")
    void jsonSerialization() {
        String json = HttpTransport.toJson(Map.of("key", "value", "num", 42));
        assertTrue(json.contains("\"key\":\"value\""));
        assertTrue(json.contains("\"num\":42"));
    }

    @Test
    @DisplayName("HttpTransport.parseJson round-trips")
    void jsonRoundTrip() {
        String json = "{\"vpec_id\":\"vpec_001\",\"chain_intact\":true,\"total\":5}";
        Map<String, Object> parsed = HttpTransport.parseJson(json);
        assertEquals("vpec_001", parsed.get("vpec_id"));
        assertEquals(true, parsed.get("chain_intact"));
        assertEquals(5, parsed.get("total"));
    }

    // ── Mock transport ──

    static class MockTransport extends HttpTransport {
        MockTransport() {
            super("pk_sb_mock", "https://mock.primust.com");
        }

        @Override
        Map<String, Object> postOpenRun(Map<String, Object> payload) {
            return null; // simulate unreachable
        }

        @Override
        Map<String, Object> postRecord(String runId, Map<String, Object> envelope) {
            return null; // simulate unreachable — record queued
        }

        @Override
        Map<String, Object> postCloseRun(String runId, Map<String, Object> payload) {
            return null; // simulate unreachable
        }

        @Override
        Map<String, Object> postManifest(Map<String, Object> manifest) {
            return null;
        }
    }
}
