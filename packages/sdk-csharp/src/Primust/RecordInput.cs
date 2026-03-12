namespace Primust;

/// <summary>
/// Input to Run.RecordAsync(). Provide check name, manifest, input bytes,
/// result, and optional details/output.
///
/// <code>
/// await run.RecordAsync(new RecordInput
/// {
///     Check = "coverage_verification",
///     ManifestId = "sha256:abc...",
///     Input = Encoding.UTF8.GetBytes(inputBinding),
///     CheckResult = CheckResult.Pass,
///     Details = new Dictionary&lt;string, object&gt; { ["claim_id"] = "CLM-001" },
///     Visibility = "opaque"
/// });
/// </code>
/// </summary>
public class RecordInput
{
    /// <summary>Governance check name (e.g., "coverage_verification").</summary>
    public required string Check { get; init; }

    /// <summary>Manifest identifier (SHA-256 hash or registered ID).</summary>
    public required string ManifestId { get; init; }

    /// <summary>
    /// Raw input bytes — committed locally via SHA-256/Poseidon2 before any transmission.
    /// The raw bytes NEVER leave your environment.
    /// </summary>
    public required byte[] Input { get; init; }

    /// <summary>Optional output bytes for verification (committed locally).</summary>
    public byte[]? Output { get; init; }

    /// <summary>Result of the governance check.</summary>
    public required CheckResult CheckResult { get; init; }

    /// <summary>Bounded metadata — key-value pairs. Must not contain sensitive data.</summary>
    public Dictionary<string, object>? Details { get; init; }

    /// <summary>Data visibility: "opaque" (default), "selective", or "transparent".</summary>
    public string Visibility { get; init; } = "opaque";
}
