package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds all primust-hook configuration.
type Config struct {
	APIKey  string `json:"api_key"`
	APIURL  string `json:"api_url"`
	LogPath string `json:"log_path"`
}

// configFile is the on-disk JSON representation.
type configFile struct {
	APIKey  string `json:"api_key,omitempty"`
	APIURL  string `json:"api_url,omitempty"`
	LogPath string `json:"log_path,omitempty"`
}

// PrimustDir returns the ~/.primust directory path.
func PrimustDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".primust"
	}
	return filepath.Join(home, ".primust")
}

// Load reads configuration from ~/.primust/config.json with env overrides.
// Environment variables always take precedence:
//   - PRIMUST_API_KEY
//   - PRIMUST_API_URL
//   - PRIMUST_HOOK_LOG
func Load() *Config {
	cfg := &Config{
		APIURL:  "https://api.primust.com",
		LogPath: filepath.Join(PrimustDir(), "hook.log"),
	}

	// Try reading config file.
	configPath := filepath.Join(PrimustDir(), "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var fc configFile
		if json.Unmarshal(data, &fc) == nil {
			if fc.APIKey != "" {
				cfg.APIKey = fc.APIKey
			}
			if fc.APIURL != "" {
				cfg.APIURL = fc.APIURL
			}
			if fc.LogPath != "" {
				cfg.LogPath = fc.LogPath
			}
		}
	}

	// Env overrides.
	if v := os.Getenv("PRIMUST_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("PRIMUST_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("PRIMUST_HOOK_LOG"); v != "" {
		cfg.LogPath = v
	}

	return cfg
}

// IsObservabilityOnly returns true when no API key is configured.
func (c *Config) IsObservabilityOnly() bool {
	return c.APIKey == ""
}
