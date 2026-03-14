package com.primust.drools;

import com.primust.core.CanonicalJson;
import com.primust.core.Commitment;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Primust governance adapter for Drools rule engine (KIE).
 * <p>
 * Wraps Drools {@code KieSession.fireAllRules()} or stateless session execution
 * with Poseidon2 commitments. Facts inserted into the session are committed
 * locally via canonical JSON → Poseidon2. Only the commitment hash transits
 * to Primust API.
 * <p>
 * Proof ceiling: mathematical (Drools rules are deterministic).
 * <p>
 * Usage:
 * <pre>{@code
 * PrimustDrools adapter = new PrimustDrools(apiKey, baseUrl, manifestId, workflowId, "opaque");
 * KieSession session = kieContainer.newKieSession();
 * session.insert(fact1);
 * session.insert(fact2);
 * int rulesFired = session.fireAllRules();
 * adapter.recordEvaluation(List.of(fact1, fact2), rulesFired, "pass");
 * }</pre>
 */
public class PrimustDrools {

    private final String apiKey;
    private final String baseUrl;
    private final String manifestId;
    private final String workflowId;
    private final String visibility;
    private final HttpClient httpClient;

    public PrimustDrools(String apiKey, String baseUrl, String manifestId,
                         String workflowId, String visibility) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl != null ? baseUrl : "https://api.primust.com";
        this.manifestId = manifestId;
        this.workflowId = workflowId;
        this.visibility = visibility != null ? visibility : "opaque";
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /**
     * Record a Drools rule evaluation with Primust governance.
     *
     * @param facts       the facts that were inserted into the session (as serializable maps)
     * @param rulesFired  the number of rules that fired
     * @param checkResult "pass" or "fail"
     * @return commitment hash of the input facts
     */
    public String recordEvaluation(List<Map<String, Object>> facts, int rulesFired,
                                   String checkResult) {
        // Canonical JSON of facts list → commitment (SHA-256 default)
        String inputJson = CanonicalJson.canonical(facts);
        var commitment = Commitment.commit(inputJson.getBytes(StandardCharsets.UTF_8));

        var details = new LinkedHashMap<String, Object>();
        details.put("rules_fired", rulesFired);
        details.put("facts_count", facts.size());

        recordCheck(commitment.hash(), checkResult, details);
        return commitment.hash();
    }

    /**
     * Record a Drools rule evaluation with rule names.
     *
     * @param facts          the facts inserted into the session
     * @param ruleNames      names of rules that fired (from KieSession.getObjects or agenda)
     * @param checkResult    "pass" or "fail"
     * @return commitment hash
     */
    public String recordEvaluationWithRules(List<Map<String, Object>> facts,
                                            List<String> ruleNames, String checkResult) {
        String inputJson = CanonicalJson.canonical(facts);
        var commitment = Commitment.commit(inputJson.getBytes(StandardCharsets.UTF_8));

        var details = new LinkedHashMap<String, Object>();
        details.put("rules_fired", ruleNames.size());
        details.put("facts_count", facts.size());
        // Rule names committed separately — don't reveal to verifier
        String rulesJson = CanonicalJson.canonical(ruleNames);
        var rulesCommitment = Commitment.commitOutput(rulesJson.getBytes(StandardCharsets.UTF_8));
        details.put("rules_commitment", rulesCommitment.hash());

        recordCheck(commitment.hash(), checkResult, details);
        return commitment.hash();
    }

    public Map<String, Object> getSurfaceDeclaration() {
        return SurfaceDeclaration.DECLARATION;
    }

    private void recordCheck(String inputCommitment, String checkResult, Map<String, Object> details) {
        try {
            var payload = new LinkedHashMap<String, Object>();
            payload.put("check", "drools_rule_evaluation");
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
                .header("X-Primust-SDK", "java-drools/0.1.0")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ignored) {
        }
    }
}
