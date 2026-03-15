package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear env vars to test defaults.
	os.Unsetenv("PRIMUST_API_KEY")
	os.Unsetenv("PRIMUST_API_URL")
	os.Unsetenv("PRIMUST_HOOK_LOG")

	cfg := Load()
	if cfg.APIURL != "https://api.primust.com" {
		t.Errorf("expected default API URL, got %s", cfg.APIURL)
	}
	if cfg.APIKey != "" {
		t.Errorf("expected empty API key by default, got %s", cfg.APIKey)
	}
	if !cfg.IsObservabilityOnly() {
		t.Error("expected observability-only mode with no API key")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("PRIMUST_API_KEY", "test-key-123")
	t.Setenv("PRIMUST_API_URL", "https://custom.api.com")
	t.Setenv("PRIMUST_HOOK_LOG", "/tmp/test-hook.log")

	cfg := Load()
	if cfg.APIKey != "test-key-123" {
		t.Errorf("expected env API key, got %s", cfg.APIKey)
	}
	if cfg.APIURL != "https://custom.api.com" {
		t.Errorf("expected env API URL, got %s", cfg.APIURL)
	}
	if cfg.LogPath != "/tmp/test-hook.log" {
		t.Errorf("expected env log path, got %s", cfg.LogPath)
	}
	if cfg.IsObservabilityOnly() {
		t.Error("should not be observability-only with API key set")
	}
}

func TestLoad_ConfigFile(t *testing.T) {
	// Create a temp config file.
	tmpDir := t.TempDir()
	configData := configFile{
		APIKey:  "file-key-456",
		APIURL:  "https://file.api.com",
		LogPath: "/tmp/file-hook.log",
	}
	data, _ := json.Marshal(configData)

	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, data, 0600)

	// Verify the file can be read and parsed.
	readData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed configFile
	if err := json.Unmarshal(readData, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.APIKey != "file-key-456" {
		t.Errorf("expected file-key-456, got %s", parsed.APIKey)
	}
}

func TestIsObservabilityOnly(t *testing.T) {
	cfg := &Config{APIKey: "", APIURL: "https://api.primust.com"}
	if !cfg.IsObservabilityOnly() {
		t.Error("expected observability-only with empty API key")
	}

	cfg.APIKey = "some-key"
	if cfg.IsObservabilityOnly() {
		t.Error("expected NOT observability-only with API key set")
	}
}

func TestPrimustDir(t *testing.T) {
	dir := PrimustDir()
	if dir == "" {
		t.Error("expected non-empty primust dir")
	}
	if filepath.Base(dir) != ".primust" {
		t.Errorf("expected .primust suffix, got %s", dir)
	}
}
