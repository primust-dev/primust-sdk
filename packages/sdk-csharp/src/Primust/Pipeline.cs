namespace Primust;

/// <summary>
/// Primust governance pipeline.
///
/// <code>
/// var pipeline = new Pipeline("pk_live_...", "claims-adjudication-v1");
/// var run = pipeline.Open();
/// await run.RecordAsync(new RecordInput { ... });
/// var vpec = await run.CloseAsync();
/// </code>
///
/// Raw input committed locally — never transmitted.
/// </summary>
public sealed class Pipeline
{
    private readonly string _apiKey;
    private readonly string _workflowId;
    private readonly string _baseUrl;
    private readonly bool _testMode;
    private readonly HttpTransport _transport;
    private string? _orgId;

    /// <summary>
    /// Create a new Pipeline.
    /// </summary>
    /// <param name="apiKey">API key (or set PRIMUST_API_KEY env var).</param>
    /// <param name="workflowId">Identifies the governed process.</param>
    /// <param name="baseUrl">API base URL (default: https://api.primust.com).</param>
    public Pipeline(string? apiKey = null, string workflowId = "default",
                    string baseUrl = "https://api.primust.com")
    {
        var key = apiKey ?? Environment.GetEnvironmentVariable("PRIMUST_API_KEY");
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException(
                "apiKey is required. Pass it directly or set PRIMUST_API_KEY env var.");

        _apiKey = key;
        _workflowId = workflowId;
        _baseUrl = baseUrl.TrimEnd('/');
        _testMode = key.StartsWith("pk_test_");
        _transport = new HttpTransport(key, _baseUrl);
    }

    /// <summary>
    /// Open a new governed process run.
    /// Returns a Run. Call RecordAsync() for each check, then CloseAsync().
    /// </summary>
    public Run Open()
    {
        var runId = $"run_{Guid.NewGuid():N}";
        // Fire-and-forget open notification — don't block
        _ = _transport.PostOpenRunAsync(new Dictionary<string, object?>
        {
            ["run_id"] = runId,
            ["workflow_id"] = _workflowId,
            ["environment"] = _testMode ? "test" : "production",
            ["opened_at"] = DateTime.UtcNow.ToString("o"),
        });

        return new Run(runId, _workflowId, _orgId ?? "unknown", _transport, _testMode);
    }

    /// <summary>Whether this pipeline uses a test key.</summary>
    public bool TestMode => _testMode;

    /// <summary>Workflow identifier.</summary>
    public string WorkflowId => _workflowId;
}
