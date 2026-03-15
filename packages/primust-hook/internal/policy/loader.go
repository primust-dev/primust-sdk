package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/primust-dev/primust-hook/internal/config"
)

// CheckConfig defines a single check's policy configuration.
type CheckConfig struct {
	Name      string  `json:"name"`
	Enabled   bool    `json:"enabled"`
	Threshold float64 `json:"threshold,omitempty"`
}

// Policy holds the active policy for this org/deployment.
type Policy struct {
	BundleID        string        `json:"bundle_id"`
	Checks          []CheckConfig `json:"checks"`
	RefreshInterval int           `json:"refresh_interval"` // seconds
}

// EmptyPolicy returns the default observability-only policy with all built-in checks enabled.
func EmptyPolicy() *Policy {
	return &Policy{
		BundleID: "default-observability",
		Checks: []CheckConfig{
			{Name: "secrets_scanner", Enabled: true},
			{Name: "pii_regex", Enabled: true},
			{Name: "command_patterns", Enabled: true},
			{Name: "cost_bounds", Enabled: true, Threshold: 100000},
		},
		RefreshInterval: 300,
	}
}

// LoadPolicy tries API first, then cache, then empty policy.
func LoadPolicy(cfg *config.Config) *Policy {
	// 1. Try API if configured.
	if cfg.APIKey != "" {
		if pol, err := fetchFromAPI(cfg); err == nil {
			_ = CachePolicy(pol)
			return pol
		}
	}

	// 2. Try cached policy.
	if pol, err := loadCached(); err == nil {
		return pol
	}

	// 3. Fall back to empty policy (observability-only mode).
	return EmptyPolicy()
}

// CachePolicy writes policy to ~/.primust/policy.json.
func CachePolicy(pol *Policy) error {
	dir := config.PrimustDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "policy.json"), data, 0600)
}

// RefreshLoop runs a goroutine that refreshes policy at the configured interval.
// The onUpdate callback is called with the new policy whenever it changes.
func RefreshLoop(cfg *config.Config, onUpdate func(*Policy)) {
	interval := 5 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if cfg.APIKey == "" {
			continue
		}
		pol, err := fetchFromAPI(cfg)
		if err != nil {
			continue
		}
		_ = CachePolicy(pol)
		if onUpdate != nil {
			onUpdate(pol)
		}
	}
}

func fetchFromAPI(cfg *config.Config) (*Policy, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", cfg.APIURL+"/api/v1/policy/active", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("User-Agent", "primust-hook/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pol Policy
	if err := json.Unmarshal(body, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

func loadCached() (*Policy, error) {
	path := filepath.Join(config.PrimustDir(), "policy.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}
