namespace Primust;

/// <summary>
/// Result of a governance check execution.
/// </summary>
public enum CheckResult
{
    Pass,
    Fail,
    Error,
    Skipped,
    Degraded,
    Override,
    NotApplicable
}

internal static class CheckResultExtensions
{
    public static string ToWireValue(this CheckResult result) => result switch
    {
        CheckResult.Pass => "pass",
        CheckResult.Fail => "fail",
        CheckResult.Error => "error",
        CheckResult.Skipped => "skipped",
        CheckResult.Degraded => "degraded",
        CheckResult.Override => "override",
        CheckResult.NotApplicable => "not_applicable",
        _ => "unknown"
    };
}
