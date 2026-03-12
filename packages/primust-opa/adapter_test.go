package primustopa

import (
	"testing"

	rulescore "github.com/primust-dev/rules-core-go"
)

func TestSurfaceDeclaration(t *testing.T) {
	adapter := New(Config{
		PrimustAPIKey: "test_key",
		ManifestID:    "manifest_123",
		WorkflowID:    "authz-v1",
	})
	decl := adapter.GetSurfaceDeclaration()

	if decl["surface_type"] != "policy_engine" {
		t.Errorf("surface_type = %v, want policy_engine", decl["surface_type"])
	}
	if decl["proof_ceiling"] != "mathematical" {
		t.Errorf("proof_ceiling = %v, want mathematical", decl["proof_ceiling"])
	}
	if decl["observation_mode"] != "instrumentation" {
		t.Errorf("observation_mode = %v, want instrumentation", decl["observation_mode"])
	}
}

func TestHashPolicy(t *testing.T) {
	policy := []byte(`package authz
default allow = false
allow { input.user == "admin" }`)
	hash := HashPolicy(policy)
	if len(hash) < 10 {
		t.Error("HashPolicy returned empty/short hash")
	}
	if hash[:7] != "sha256:" {
		t.Errorf("HashPolicy should return sha256: prefix, got %s", hash[:7])
	}
	// Deterministic
	hash2 := HashPolicy(policy)
	if hash != hash2 {
		t.Error("HashPolicy should be deterministic")
	}
}

func TestInputCommitment(t *testing.T) {
	// Verify that canonical JSON → Poseidon2 commitment works for OPA-style inputs
	input := map[string]interface{}{
		"user":     "alice",
		"action":   "read",
		"resource": "/data/reports",
	}
	jsonStr, err := rulescore.Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	// Keys should be sorted
	expected := `{"action":"read","resource":"/data/reports","user":"alice"}`
	if jsonStr != expected {
		t.Errorf("Canonical = %s, want %s", jsonStr, expected)
	}

	commitment := rulescore.CommitDefault([]byte(jsonStr))
	if commitment.Algorithm != "sha256" {
		t.Error("Expected sha256 algorithm (default)")
	}
	if len(commitment.Hash) < 10 {
		t.Error("Commitment hash too short")
	}
}

func TestDefaultVisibility(t *testing.T) {
	adapter := New(Config{
		PrimustAPIKey: "test_key",
	})
	if adapter.config.Visibility != "opaque" {
		t.Errorf("Default visibility = %s, want opaque", adapter.config.Visibility)
	}
}

func TestProofLevelPolicyEngine(t *testing.T) {
	level, err := rulescore.SelectProofLevel("policy_engine")
	if err != nil {
		t.Fatal(err)
	}
	if level != "mathematical" {
		t.Errorf("policy_engine proof level = %s, want mathematical", level)
	}
}
