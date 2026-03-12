namespace Primust;

/// <summary>
/// Verifiable Process Execution Credential.
/// Returned by Run.CloseAsync(). Portable, offline-verifiable.
/// </summary>
public sealed class VpecResult
{
    /// <summary>Unique VPEC identifier.</summary>
    public string VpecId { get; init; } = "";

    /// <summary>Run identifier.</summary>
    public string RunId { get; init; } = "";

    /// <summary>Workflow identifier.</summary>
    public string WorkflowId { get; init; } = "";

    /// <summary>Organization identifier.</summary>
    public string OrgId { get; init; } = "";

    /// <summary>ISO 8601 timestamp of issuance.</summary>
    public string IssuedAt { get; init; } = "";

    /// <summary>Weakest-link proof level across all checks.</summary>
    public string ProofLevel { get; init; } = "attestation";

    /// <summary>Total governance checks executed.</summary>
    public int TotalChecksRun { get; init; }

    /// <summary>Checks that passed.</summary>
    public int ChecksPassed { get; init; }

    /// <summary>Checks that failed.</summary>
    public int ChecksFailed { get; init; }

    /// <summary>Governance gaps detected.</summary>
    public List<GovernanceGap> GovernanceGaps { get; init; } = new();

    /// <summary>True if commitment chain is unbroken.</summary>
    public bool ChainIntact { get; init; }

    /// <summary>True if pk_test_ key was used.</summary>
    public bool TestMode { get; init; }

    /// <summary>True if chain is intact AND zero governance gaps.</summary>
    public bool IsClean => ChainIntact && GovernanceGaps.Count == 0;
}

/// <summary>
/// A governance gap recorded in the VPEC.
/// </summary>
public sealed class GovernanceGap
{
    public string GapId { get; init; } = "";
    public string GapType { get; init; } = "";
    public string Severity { get; init; } = "";
    public string? Check { get; init; }
    public int? Sequence { get; init; }
    public string Timestamp { get; init; } = "";
}
