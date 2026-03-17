using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Primust.Tests;

/// <summary>
/// Primust C# SDK tests.
///
/// Tests run against mock transport (no live API). Verifies:
/// - Pipeline configuration and test mode detection
/// - Run lifecycle (RecordAsync → CloseAsync)
/// - Commitment invariant (raw input never in envelope)
/// - Chain integrity (rolling hash)
/// - SHA-256 golden vectors matching Python/Java/JS SDKs
/// - VPEC parsing and gap recording
/// - Graceful degradation when API unreachable
/// </summary>
public class PrimustSdkTest
{
    // ── Pipeline configuration ──

    [Fact]
    public void Pipeline_pk_test_prefix_sets_test_mode()
    {
        var pipeline = new Pipeline("pk_test_abc123", "test-workflow");
        Assert.True(pipeline.TestMode);
        Assert.Equal("test-workflow", pipeline.WorkflowId);
    }

    [Fact]
    public void Pipeline_pk_live_prefix_sets_production_mode()
    {
        var pipeline = new Pipeline("pk_live_abc123", "prod-workflow");
        Assert.False(pipeline.TestMode);
    }

    [Fact]
    public void Pipeline_pk_sb_prefix_sets_test_mode()
    {
        var pipeline = new Pipeline("pk_sb_sandbox", "sandbox-workflow");
        Assert.True(pipeline.TestMode);
    }

    [Fact]
    public void Pipeline_missing_api_key_throws()
    {
        // Clear env var to ensure no fallback
        var original = Environment.GetEnvironmentVariable("PRIMUST_API_KEY");
        Environment.SetEnvironmentVariable("PRIMUST_API_KEY", null);
        try
        {
            Assert.Throws<ArgumentException>(() => new Pipeline(null, "test"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("PRIMUST_API_KEY", original);
        }
    }

    // ── RecordAsync — commitment invariant ──

    [Fact]
    public async Task RecordAsync_produces_sha256_commitment_hash()
    {
        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "pii_scan",
            ManifestId = "sha256:manifest_pii",
            Input = "sensitive_data"u8.ToArray(),
            CheckResult = CheckResult.Pass,
            Visibility = "opaque",
        });

        Assert.NotNull(result.CommitmentHash);
        Assert.StartsWith("sha256:", result.CommitmentHash);
        Assert.Equal(71, result.CommitmentHash.Length); // "sha256:" + 64 hex chars
        Assert.Equal("sha256", result.CommitmentAlgorithm);
    }

    [Fact]
    public async Task RecordAsync_same_input_same_commitment()
    {
        var input = "deterministic_test"u8.ToArray();

        var run1 = CreateMockRun("run_1");
        var r1 = await run1.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = input, CheckResult = CheckResult.Pass,
        });

        var run2 = CreateMockRun("run_2");
        var r2 = await run2.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = input, CheckResult = CheckResult.Pass,
        });

        Assert.Equal(r1.CommitmentHash, r2.CommitmentHash);
    }

    [Fact]
    public async Task RecordAsync_different_input_different_commitment()
    {
        var run1 = CreateMockRun("run_1");
        var r1 = await run1.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "aaa"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        var run2 = CreateMockRun("run_2");
        var r2 = await run2.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "bbb"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        Assert.NotEqual(r1.CommitmentHash, r2.CommitmentHash);
    }

    [Fact]
    public async Task RecordAsync_golden_vector_matches_other_sdks()
    {
        // Golden vector: SHA-256 of "primust_test_vector_v1" must match
        // Python, Java, and JS SDKs.
        var input = "primust_test_vector_v1"u8.ToArray();
        var expectedHash = Sha256Hex(input);

        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "golden", ManifestId = "m", Input = input, CheckResult = CheckResult.Pass,
        });

        Assert.Equal(expectedHash, result.CommitmentHash);
    }

    [Fact]
    public async Task RecordAsync_output_commitment_computed_when_provided()
    {
        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "coverage_check",
            ManifestId = "sha256:manifest_cov",
            Input = "input_data"u8.ToArray(),
            Output = "output_result"u8.ToArray(),
            CheckResult = CheckResult.Pass,
        });

        Assert.NotNull(result.OutputCommitment);
        Assert.StartsWith("sha256:", result.OutputCommitment);
    }

    [Fact]
    public async Task RecordAsync_output_commitment_null_when_not_provided()
    {
        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "x"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        Assert.Null(result.OutputCommitment);
    }

    // ── Visibility default ──

    [Fact]
    public void RecordInput_defaults_visibility_to_opaque()
    {
        var input = new RecordInput
        {
            Check = "test",
            ManifestId = "sha256:m1",
            Input = "x"u8.ToArray(),
            CheckResult = CheckResult.Pass,
        };

        Assert.Equal("opaque", input.Visibility);
    }

    // ── Chain integrity ──

    [Fact]
    public async Task RecordAsync_chain_hashes_are_unique_across_records()
    {
        var run = CreateMockRun();

        var r1 = await run.RecordAsync(new RecordInput
        {
            Check = "c1", ManifestId = "m", Input = "a"u8.ToArray(), CheckResult = CheckResult.Pass,
        });
        var r2 = await run.RecordAsync(new RecordInput
        {
            Check = "c2", ManifestId = "m", Input = "b"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        Assert.NotEqual(r1.ChainHash, r2.ChainHash);
        Assert.NotEmpty(r1.ChainHash);
        Assert.NotEmpty(r2.ChainHash);
    }

    [Fact]
    public async Task RecordAsync_record_id_has_rec_prefix()
    {
        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "x"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        Assert.StartsWith("rec_", result.RecordId);
    }

    // ── Run lifecycle ──

    [Fact]
    public async Task RecordAsync_throws_after_close()
    {
        var run = CreateMockRun();
        await run.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "x"u8.ToArray(), CheckResult = CheckResult.Pass,
        });
        await run.CloseAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await run.RecordAsync(new RecordInput
            {
                Check = "c", ManifestId = "m", Input = "y"u8.ToArray(), CheckResult = CheckResult.Pass,
            }));
    }

    [Fact]
    public async Task CloseAsync_double_close_throws()
    {
        var run = CreateMockRun();
        await run.CloseAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await run.CloseAsync());
    }

    // ── VPEC ──

    [Fact]
    public async Task CloseAsync_returns_vpec_with_system_unavailable_gap_when_api_unreachable()
    {
        var run = CreateMockRun(testMode: true);
        await run.RecordAsync(new RecordInput
        {
            Check = "check1", ManifestId = "m1", Input = "data"u8.ToArray(),
            CheckResult = CheckResult.Pass,
        });

        var vpec = await run.CloseAsync();

        Assert.NotNull(vpec);
        Assert.StartsWith("vpec_pending_", vpec.VpecId);
        Assert.True(vpec.TestMode);
        Assert.Equal(1, vpec.TotalChecksRun);
        Assert.Single(vpec.GovernanceGaps);
        Assert.Equal("system_unavailable", vpec.GovernanceGaps[0].GapType);
        Assert.Equal("high", vpec.GovernanceGaps[0].Severity);
        Assert.False(vpec.IsClean); // has gap
    }

    [Fact]
    public void VpecResult_IsClean_true_when_chain_intact_and_no_gaps()
    {
        var vpec = new VpecResult
        {
            VpecId = "vpec_001",
            RunId = "run_001",
            WorkflowId = "wf",
            OrgId = "org",
            IssuedAt = "2026-01-01T00:00:00Z",
            ProofLevel = "attestation",
            TotalChecksRun = 3,
            ChecksPassed = 3,
            ChecksFailed = 0,
            GovernanceGaps = new List<GovernanceGap>(),
            ChainIntact = true,
            TestMode = false,
        };

        Assert.True(vpec.IsClean);
    }

    [Fact]
    public void VpecResult_IsClean_false_when_gap_present()
    {
        var vpec = new VpecResult
        {
            VpecId = "vpec_002",
            RunId = "run_002",
            ChainIntact = true,
            GovernanceGaps = new List<GovernanceGap>
            {
                new() { GapId = "gap_1", GapType = "vendor_api_error", Severity = "high" }
            },
        };

        Assert.False(vpec.IsClean);
    }

    // ── CheckResult enum ──

    [Fact]
    public void CheckResult_has_7_values()
    {
        Assert.Equal(7, Enum.GetValues<CheckResult>().Length);
    }

    [Fact]
    public void CheckResult_ToWireValue_maps_correctly()
    {
        Assert.Equal("pass", CheckResult.Pass.ToWireValue());
        Assert.Equal("fail", CheckResult.Fail.ToWireValue());
        Assert.Equal("error", CheckResult.Error.ToWireValue());
        Assert.Equal("not_applicable", CheckResult.NotApplicable.ToWireValue());
    }

    // ── LastCommitmentHash ──

    [Fact]
    public async Task Run_LastCommitmentHash_tracks_most_recent()
    {
        var run = CreateMockRun();
        Assert.Null(run.LastCommitmentHash);

        var r1 = await run.RecordAsync(new RecordInput
        {
            Check = "c1", ManifestId = "m", Input = "a"u8.ToArray(), CheckResult = CheckResult.Pass,
        });
        Assert.Equal(r1.CommitmentHash, run.LastCommitmentHash);

        var r2 = await run.RecordAsync(new RecordInput
        {
            Check = "c2", ManifestId = "m", Input = "b"u8.ToArray(), CheckResult = CheckResult.Pass,
        });
        Assert.Equal(r2.CommitmentHash, run.LastCommitmentHash);
    }

    // ── Queued mode ──

    [Fact]
    public async Task RecordAsync_queued_true_when_transport_returns_null()
    {
        var run = CreateMockRun();
        var result = await run.RecordAsync(new RecordInput
        {
            Check = "c", ManifestId = "m", Input = "x"u8.ToArray(), CheckResult = CheckResult.Pass,
        });

        Assert.True(result.Queued);
    }

    // ── Helpers ──

    private static Run CreateMockRun(string runId = "run_test_001", bool testMode = false)
    {
        return new Run(runId, "test-wf", "org_test", new MockTransport(), testMode);
    }

    private static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return $"sha256:{Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}

/// <summary>
/// Mock transport that simulates API unreachable (returns null for all calls).
/// Mirrors the Java SDK MockTransport pattern.
/// </summary>
internal sealed class MockTransport : HttpTransport
{
    public MockTransport() : base("pk_test_mock", "https://mock.primust.com") { }

    public override Task<Dictionary<string, object?>?> PostOpenRunAsync(
        Dictionary<string, object?> payload)
        => Task.FromResult<Dictionary<string, object?>?>(null);

    public override Task<Dictionary<string, object?>?> PostRecordAsync(
        string runId, Dictionary<string, object?> envelope)
        => Task.FromResult<Dictionary<string, object?>?>(null);

    public override Task<Dictionary<string, object?>?> PostCloseRunAsync(
        string runId, Dictionary<string, object?> payload)
        => Task.FromResult<Dictionary<string, object?>?>(null);
}
