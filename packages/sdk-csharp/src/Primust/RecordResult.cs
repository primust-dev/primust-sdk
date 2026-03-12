namespace Primust;

/// <summary>
/// Returned by Run.RecordAsync().
/// Write CommitmentHash to your operational logs for log linkage.
/// </summary>
public sealed class RecordResult
{
    /// <summary>Unique record identifier.</summary>
    public string RecordId { get; init; } = "";

    /// <summary>
    /// Log linkage anchor — write to your operational logs alongside the
    /// transaction ID. Connects your logs to the VPEC.
    /// </summary>
    public string CommitmentHash { get; init; } = "";

    /// <summary>Output commitment hash (if output was provided).</summary>
    public string? OutputCommitment { get; init; }

    /// <summary>Hash algorithm used: "sha256" or "poseidon2".</summary>
    public string CommitmentAlgorithm { get; init; } = "sha256";

    /// <summary>Proof level achieved.</summary>
    public string ProofLevel { get; init; } = "attestation";

    /// <summary>ISO 8601 timestamp of recording.</summary>
    public string RecordedAt { get; init; } = "";

    /// <summary>Rolling chain integrity hash.</summary>
    public string ChainHash { get; init; } = "";

    /// <summary>True if API was unreachable — record queued locally.</summary>
    public bool Queued { get; init; }
}
