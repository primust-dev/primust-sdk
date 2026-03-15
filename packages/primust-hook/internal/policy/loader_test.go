package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/primust-dev/primust-hook/internal/config"
)

func TestEmptyPolicy(t *testing.T) {
	pol := EmptyPolicy()
	if pol.BundleID != "default-observability" {
		t.Errorf("expected default-observability bundle, got %s", pol.BundleID)
	}
	if len(pol.Checks) != 4 {
		t.Errorf("expected 4 default checks, got %d", len(pol.Checks))
	}
	for _, c := range pol.Checks {
		if !c.Enabled {
			t.Errorf("expected check %s to be enabled", c.Name)
		}
	}
}

func TestLoadPolicy_FallbackToEmpty(t *testing.T) {
	// No API key, no cache — should return empty policy.
	cfg := &config.Config{
		APIURL: "https://api.primust.com",
	}
	pol := LoadPolicy(cfg)
	if pol.BundleID != "default-observability" {
		t.Errorf("expected fallback to empty policy, got bundle=%s", pol.BundleID)
	}
}

func TestCachePolicy_AndReload(t *testing.T) {
	// Create a temp dir to act as ~/.primust.
	tmpDir := t.TempDir()

	// Override PrimustDir by writing cache directly.
	pol := &Policy{
		BundleID: "test-bundle-123",
		Checks: []CheckConfig{
			{Name: "secrets_scanner", Enabled: true},
			{Name: "pii_regex", Enabled: false},
		},
		RefreshInterval: 60,
	}

	data, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	cachePath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Read it back.
	readData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	var loaded Policy
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatal(err)
	}

	if loaded.BundleID != "test-bundle-123" {
		t.Errorf("expected test-bundle-123, got %s", loaded.BundleID)
	}
	if len(loaded.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(loaded.Checks))
	}
	if loaded.Checks[1].Enabled {
		t.Error("expected pii_regex to be disabled")
	}
}

func TestPolicyJSON_RoundTrip(t *testing.T) {
	pol := &Policy{
		BundleID: "org-acme-prod",
		Checks: []CheckConfig{
			{Name: "secrets_scanner", Enabled: true, Threshold: 0},
			{Name: "cost_bounds", Enabled: true, Threshold: 50000},
		},
		RefreshInterval: 300,
	}

	data, err := json.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}

	var parsed Policy
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.BundleID != pol.BundleID {
		t.Errorf("bundle_id mismatch: %s != %s", parsed.BundleID, pol.BundleID)
	}
	if parsed.Checks[1].Threshold != 50000 {
		t.Errorf("threshold mismatch: %f != 50000", parsed.Checks[1].Threshold)
	}
}
