package com.primust.cedar;

import com.primust.core.CanonicalJson;
import com.primust.core.Commitment;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Primust governance adapter for AWS Cedar authorization engine.
 * <p>
 * Wraps Cedar {@code isAuthorized()} calls with Poseidon2 commitments.
 * The request (principal, action, resource, context) is committed locally
 * via canonical JSON → Poseidon2. Only the commitment hash transits to
 * Primust API. Raw authorization data never leaves the customer environment.
 * <p>
 * Proof ceiling: mathematical (Cedar policies are deterministic).
 */
public class PrimustCedar {

    private final String apiKey;
    private final String baseUrl;
    private final String manifestId;
    private final String workflowId;
    private final String visibility;
    private final String policySetHash;
    private final HttpClient httpClient;

    public PrimustCedar(String apiKey, String baseUrl, String manifestId,
                        String workflowId, String policySetHash, String visibility) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl != null ? baseUrl : "https://api.primust.com";
        this.manifestId = manifestId;
        this.workflowId = workflowId;
        this.policySetHash = policySetHash;
        this.visibility = visibility != null ? visibility : "opaque";
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /**
     * Record an authorization evaluation with Primust governance.
     *
     * @param principal   Cedar principal entity (e.g., "User::\"alice\"")
     * @param action      Cedar action (e.g., "Action::\"read\"")
     * @param resource    Cedar resource (e.g., "Document::\"report-1\"")
     * @param context     Cedar context map
     * @param decision    the Cedar decision result ("allow" or "deny")
     * @param diagnostics Cedar diagnostics (reasons, errors)
     * @return commitment hash of the input
     */
    public String recordEvaluation(
            String principal, String action, String resource,
            Map<String, Object> context, String decision,
            Map<String, Object> diagnostics) {

        // Build canonical input
        var input = new LinkedHashMap<String, Object>();
        input.put("action", action);
        input.put("context", context != null ? context : Map.of());
        input.put("principal", principal);
        input.put("resource", resource);

        String inputJson = CanonicalJson.canonical(input);
        var commitment = Commitment.commit(inputJson.getBytes(StandardCharsets.UTF_8));

        // Determine check result
        String checkResult = "allow".equals(decision) ? "pass" : "fail";

        // Record to Primust API
        var details = new LinkedHashMap<String, Object>();
        details.put("policy_set_hash", policySetHash);
        details.put("decision", decision);
        if (diagnostics != null && diagnostics.containsKey("reasons")) {
            details.put("reasons_count", ((java.util.List<?>) diagnostics.get("reasons")).size());
        }

        recordCheck(commitment.hash(), checkResult, details);
        return commitment.hash();
    }

    public Map<String, Object> getSurfaceDeclaration() {
        return SurfaceDeclaration.DECLARATION;
    }

    private void recordCheck(String inputCommitment, String checkResult, Map<String, Object> details) {
        try {
            var payload = new LinkedHashMap<String, Object>();
            payload.put("check", "cedar_policy_evaluation");
            payload.put("manifest_id", manifestId);
            payload.put("input_commitment", inputCommitment);
            payload.put("check_result", checkResult);
            payload.put("proof_level_achieved", "mathematical");
            payload.put("visibility", visibility);
            payload.put("details", details);

            String body = CanonicalJson.canonical(payload);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/v1/runs/" + workflowId + "/records"))
                .header("Content-Type", "application/json")
                .header("X-API-Key", apiKey)
                .header("X-Primust-SDK", "java-cedar/0.1.0")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ignored) {
            // Governance recording failure should not block authorization
        }
    }
}
