using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Primust;

/// <summary>
/// A governed process run. Opened by Pipeline.Open().
///
/// <code>
/// var run = pipeline.Open();
/// var result = await run.RecordAsync(new RecordInput { ... });
/// var vpec = await run.CloseAsync();
/// </code>
///
/// INVARIANT: Raw input bytes are committed locally via SHA-256
/// before anything is transmitted. The transport layer never receives raw values.
/// </summary>
public sealed class Run
{
    private readonly string _runId;
    private readonly string _workflowId;
    private readonly string _orgId;
    private readonly HttpTransport _transport;
    private readonly bool _testMode;
    private readonly object _lock = new();
    private bool _closed;
    private int _sequence;
    private string _chainHash = "";
    private readonly List<string> _recordIds = new();
    private readonly List<string> _proofLevels = new();
    private string? _lastCommitmentHash;

    internal Run(string runId, string workflowId, string orgId,
                 HttpTransport transport, bool testMode)
    {
        _runId = runId;
        _workflowId = workflowId;
        _orgId = orgId;
        _transport = transport;
        _testMode = testMode;
    }

    /// <summary>Most recent commitment hash from RecordAsync.</summary>
    public string? LastCommitmentHash => _lastCommitmentHash;

    /// <summary>
    /// Record a governance check execution.
    /// Raw input committed locally — never transmitted to api.primust.com.
    /// </summary>
    public async Task<RecordResult> RecordAsync(RecordInput input)
    {
        lock (_lock)
        {
            if (_closed)
                throw new InvalidOperationException("Cannot record on a closed Run.");
        }

        var recordId = $"rec_{Guid.NewGuid():N}";
        int seq;
        lock (_lock) { seq = _sequence++; }
        var recordedAt = DateTime.UtcNow.ToString("o");

        // ── LOCAL COMMITMENT — raw input never leaves ──
        var commitmentHash = Sha256Hex(input.Input);
        var algorithm = "sha256";

        string? outputCommitment = null;
        if (input.Output != null)
            outputCommitment = Sha256Hex(input.Output);
        // ────────────────────────────────────────────────

        string chainHash;
        lock (_lock)
        {
            var chainInput = $"{_chainHash}|{recordId}|{commitmentHash}|{seq}";
            _chainHash = Sha256Hex(Encoding.UTF8.GetBytes(chainInput));
            chainHash = _chainHash;
            _proofLevels.Add("attestation");
            _recordIds.Add(recordId);
            _lastCommitmentHash = commitmentHash;
        }

        // Build envelope — ONLY hashes and metadata, never raw values
        var envelope = new Dictionary<string, object?>
        {
            ["record_id"] = recordId,
            ["run_id"] = _runId,
            ["manifest_id"] = input.ManifestId,
            ["check"] = input.Check,
            ["sequence"] = seq,
            ["check_result"] = input.CheckResult.ToWireValue(),
            ["commitment_hash"] = commitmentHash,
            ["commitment_algorithm"] = algorithm,
            ["commitment_type"] = input.Output == null ? "input_only" : "input_output",
            ["proof_level_achieved"] = "attestation",
            ["visibility"] = input.Visibility,
            ["chain_hash"] = chainHash,
            ["recorded_at"] = recordedAt,
            ["idempotency_key"] = $"idem_{Guid.NewGuid():N}"[..20],
        };

        if (outputCommitment != null)
            envelope["output_commitment"] = outputCommitment;
        if (input.Details != null && input.Details.Count > 0)
            envelope["details"] = input.Details;

        // ── TRANSMIT — only the envelope (no raw data) ──
        var response = await _transport.PostRecordAsync(_runId, envelope);
        var queued = response == null;

        var proofLevel = "attestation";
        if (response?.ContainsKey("proof_level") == true)
            proofLevel = response["proof_level"]?.ToString() ?? "attestation";

        return new RecordResult
        {
            RecordId = recordId,
            CommitmentHash = commitmentHash,
            OutputCommitment = outputCommitment,
            CommitmentAlgorithm = algorithm,
            ProofLevel = proofLevel,
            RecordedAt = recordedAt,
            ChainHash = chainHash,
            Queued = queued,
        };
    }

    /// <summary>
    /// Record a system error. The run remains open.
    /// Used by connectors for graceful degradation — governance failures
    /// should not block business logic.
    /// </summary>
    public void RecordSystemError(string message)
    {
        // Log locally — system errors don't produce records
        Console.Error.WriteLine($"[Primust] System error in run {_runId}: {message}");
    }

    /// <summary>
    /// Close the run and request VPEC issuance.
    /// After close, no further records can be added.
    /// </summary>
    public async Task<VpecResult> CloseAsync()
    {
        lock (_lock)
        {
            if (_closed)
                throw new InvalidOperationException("Run already closed.");
            _closed = true;
        }

        var closedAt = DateTime.UtcNow.ToString("o");
        var overallProofLevel = WeakestLinkProofLevel();

        var payload = new Dictionary<string, object?>
        {
            ["run_id"] = _runId,
            ["record_ids"] = _recordIds.ToList(),
            ["final_chain_hash"] = _chainHash,
            ["closed_at"] = closedAt,
            ["record_count"] = _recordIds.Count,
        };

        var response = await _transport.PostCloseRunAsync(_runId, payload);

        if (response == null)
        {
            return new VpecResult
            {
                VpecId = $"vpec_pending_{_runId}",
                RunId = _runId,
                WorkflowId = _workflowId,
                OrgId = _orgId,
                IssuedAt = closedAt,
                ProofLevel = overallProofLevel,
                TotalChecksRun = _recordIds.Count,
                GovernanceGaps = new List<GovernanceGap>
                {
                    new()
                    {
                        GapId = $"gap_{Guid.NewGuid():N}"[..20],
                        GapType = "system_unavailable",
                        Severity = "high",
                        Timestamp = closedAt,
                    }
                },
                ChainIntact = true,
                TestMode = _testMode,
            };
        }

        return ParseVpec(response, overallProofLevel, closedAt);
    }

    private string WeakestLinkProofLevel()
    {
        string[] order = { "attestation", "witnessed", "execution", "verifiable_inference", "mathematical" };
        if (_proofLevels.Count == 0) return "attestation";
        foreach (var level in order)
            if (_proofLevels.Contains(level)) return level;
        return "attestation";
    }

    private VpecResult ParseVpec(Dictionary<string, object?> data,
                                  string localProofLevel, string closedAt)
    {
        return new VpecResult
        {
            VpecId = data.GetValueOrDefault("vpec_id")?.ToString() ?? $"vpec_{_runId}",
            RunId = _runId,
            WorkflowId = _workflowId,
            OrgId = data.GetValueOrDefault("org_id")?.ToString() ?? _orgId,
            IssuedAt = data.GetValueOrDefault("issued_at")?.ToString() ?? closedAt,
            ProofLevel = data.GetValueOrDefault("proof_level")?.ToString() ?? localProofLevel,
            TotalChecksRun = _recordIds.Count,
            ChainIntact = true,
            TestMode = _testMode,
        };
    }

    private static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return $"sha256:{Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}
