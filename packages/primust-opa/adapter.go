// Package primustopa provides a Primust governance adapter for Open Policy Agent.
//
// It wraps OPA policy evaluation with Primust instrumentation, computing
// Poseidon2 commitments over policy inputs and recording check results
// to produce VPECs (Verified Process Evidence Credentials).
//
// Surface type: policy_engine
// Proof ceiling: mathematical (deterministic policy evaluation)
package primustopa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	rulescore "github.com/primust-dev/rules-core-go"

	"github.com/open-policy-agent/opa/v1/rego"
)

// SurfaceDeclaration describes this adapter's instrumentation metadata.
var SurfaceDeclaration = map[string]interface{}{
	"surface_type":     "policy_engine",
	"observation_mode": "instrumentation",
	"scope_type":       "per_evaluation",
	"proof_ceiling":    "mathematical",
	"adapter":          "primust-opa",
	"engine":           "Open Policy Agent",
}

// Config holds adapter configuration.
type Config struct {
	// PrimustAPIKey is the API key for the Primust service.
	PrimustAPIKey string

	// PrimustBaseURL is the Primust API base URL.
	PrimustBaseURL string

	// ManifestID is the registered check manifest ID.
	ManifestID string

	// WorkflowID identifies the governance workflow (e.g., "authz-v1").
	WorkflowID string

	// PolicyHash is the SHA-256 hash of the .rego policy file content.
	// Used to bind the evaluation to a specific policy version.
	PolicyHash string

	// Visibility controls what the VPEC verifier can see.
	// Default: "opaque" — proves evaluation ran without revealing input/output.
	Visibility string
}

// EvalResult holds the result of an instrumented OPA evaluation.
type EvalResult struct {
	// ResultSet is the raw OPA result.
	ResultSet rego.ResultSet

	// Allowed is true if the policy evaluation produced an "allow" decision.
	Allowed bool

	// CommitmentHash is the Poseidon2 commitment of the input.
	CommitmentHash string

	// RecordID is the Primust record ID for this evaluation.
	RecordID string
}

// PrimustOPA wraps OPA policy evaluation with Primust governance.
type PrimustOPA struct {
	config Config
	client *http.Client
}

// New creates a new PrimustOPA adapter.
func New(config Config) *PrimustOPA {
	if config.Visibility == "" {
		config.Visibility = "opaque"
	}
	if config.PrimustBaseURL == "" {
		config.PrimustBaseURL = "https://api.primust.com"
	}
	return &PrimustOPA{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Eval evaluates a prepared OPA query with Primust instrumentation.
//
// The input is committed locally (SHA-256 default, Poseidon2 opt-in via
// PRIMUST_COMMITMENT_ALGORITHM env var) before any network call.
// Only the commitment hash transits to the Primust API — the raw input
// never leaves the customer environment.
func (p *PrimustOPA) Eval(ctx context.Context, query rego.PreparedEvalQuery, input interface{}) (*EvalResult, error) {
	// 1. Canonical JSON of input → commitment (SHA-256 default)
	inputJSON, err := rulescore.Canonical(input)
	if err != nil {
		return nil, fmt.Errorf("primust-opa: canonical JSON failed: %w", err)
	}
	commitment := rulescore.CommitDefault([]byte(inputJSON))

	// 2. Evaluate OPA policy
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Record the failure
		p.recordCheck(commitment.Hash, "error", nil)
		return nil, fmt.Errorf("primust-opa: OPA eval failed: %w", err)
	}

	// 3. Determine check result
	allowed := isAllowed(rs)
	checkResult := "pass"
	if !allowed {
		checkResult = "fail"
	}

	// 4. Commit output
	outputJSON, _ := json.Marshal(rs)
	outputCommitment := rulescore.CommitOutput(outputJSON)

	// 5. Record to Primust
	recordID := p.recordCheck(commitment.Hash, checkResult, map[string]interface{}{
		"output_commitment": outputCommitment.Hash,
		"policy_hash":       p.config.PolicyHash,
		"rules_evaluated":   len(rs),
	})

	return &EvalResult{
		ResultSet:      rs,
		Allowed:        allowed,
		CommitmentHash: commitment.Hash,
		RecordID:       recordID,
	}, nil
}

// HashPolicy computes the SHA-256 hash of a policy file's content.
func HashPolicy(policyContent []byte) string {
	h := sha256.Sum256(policyContent)
	return fmt.Sprintf("sha256:%064x", h)
}

// GetSurfaceDeclaration returns the adapter's surface declaration.
func (p *PrimustOPA) GetSurfaceDeclaration() map[string]interface{} {
	return SurfaceDeclaration
}

// ── Internal ──

func isAllowed(rs rego.ResultSet) bool {
	if len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		for _, expr := range r.Expressions {
			if b, ok := expr.Value.(bool); ok && b {
				return true
			}
		}
	}
	return false
}

func (p *PrimustOPA) recordCheck(inputCommitment string, checkResult string, details map[string]interface{}) string {
	payload := map[string]interface{}{
		"check":            "opa_policy_evaluation",
		"manifest_id":      p.config.ManifestID,
		"input_commitment": inputCommitment,
		"check_result":     checkResult,
		"visibility":       p.config.Visibility,
		"details":          details,
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/v1/runs/%s/records", p.config.PrimustBaseURL, p.config.WorkflowID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.config.PrimustAPIKey)
	req.Header.Set("X-Primust-SDK", "go-opa/0.1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		RecordID string `json:"record_id"`
	}
	respBody, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBody, &result)
	return result.RecordID
}
