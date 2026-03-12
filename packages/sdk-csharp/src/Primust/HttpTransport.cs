using System.Text;
using System.Text.Json;

namespace Primust;

/// <summary>
/// HTTP transport for Primust API. Raw data never transits —
/// only commitment hashes and bounded metadata.
///
/// Returns null when API is unreachable (caller handles graceful degradation).
/// </summary>
internal sealed class HttpTransport
{
    private readonly string _apiKey;
    private readonly string _baseUrl;
    private readonly HttpClient _client;

    public HttpTransport(string apiKey, string baseUrl)
    {
        _apiKey = apiKey;
        _baseUrl = baseUrl.EndsWith("/api/v1") ? baseUrl : $"{baseUrl}/api/v1";
        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public Task<Dictionary<string, object?>?> PostOpenRunAsync(
        Dictionary<string, object?> payload)
        => PostAsync("/runs", payload);

    public Task<Dictionary<string, object?>?> PostRecordAsync(
        string runId, Dictionary<string, object?> envelope)
        => PostAsync($"/runs/{runId}/records", envelope);

    public Task<Dictionary<string, object?>?> PostCloseRunAsync(
        string runId, Dictionary<string, object?> payload)
        => PostAsync($"/runs/{runId}/close", payload);

    private async Task<Dictionary<string, object?>?> PostAsync(
        string path, Dictionary<string, object?> body)
    {
        try
        {
            var json = JsonSerializer.Serialize(body,
                new JsonSerializerOptions { WriteIndented = false });

            var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}{path}")
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            request.Headers.Add("X-API-Key", _apiKey);

            var response = await _client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<Dictionary<string, object?>>(responseJson);
            }

            return null; // queued
        }
        catch
        {
            return null; // API unreachable — record queued
        }
    }
}
