package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/primust-dev/primust-hook/internal/config"
)

// Client handles API communication.
// Zero content transit: only commitment hashes + check pass/fail booleans are sent.
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewClient creates a new API client. The HTTP client has a 2s timeout
// so it never blocks the IDE.
func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// CommitmentPayload is the wire format sent to the API.
// Only hashes and booleans — never raw content.
type CommitmentPayload struct {
	Timestamp      string              `json:"timestamp"`
	Tool           string              `json:"tool"`
	CommitmentHash string              `json:"commitment_hash"`
	CheckSummaries []CheckSummary      `json:"check_summaries"`
	AllPassed      bool                `json:"all_passed"`
}

// CheckSummary is the minimal check result sent over the wire.
type CheckSummary struct {
	Name         string `json:"name"`
	Pass         bool   `json:"pass"`
	FindingCount int    `json:"finding_count"`
}

// SendCommitment sends check results + commitment hash to the API.
// This is fire-and-forget: errors are silently ignored to never block.
func (c *Client) SendCommitment(result interface{}) {
	// Extract fields from the generic result via JSON round-trip.
	data, err := json.Marshal(result)
	if err != nil {
		return
	}

	var parsed struct {
		Timestamp      string `json:"timestamp"`
		Tool           string `json:"tool"`
		CommitmentHash string `json:"commitment_hash"`
		CheckResults   []struct {
			Name     string   `json:"name"`
			Pass     bool     `json:"pass"`
			Findings []string `json:"findings"`
		} `json:"check_results"`
		AllPassed bool `json:"all_passed"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return
	}

	// Build the minimal payload — no content, only hashes and booleans.
	payload := CommitmentPayload{
		Timestamp:      parsed.Timestamp,
		Tool:           parsed.Tool,
		CommitmentHash: parsed.CommitmentHash,
		AllPassed:      parsed.AllPassed,
	}
	for _, cr := range parsed.CheckResults {
		payload.CheckSummaries = append(payload.CheckSummaries, CheckSummary{
			Name:         cr.Name,
			Pass:         cr.Pass,
			FindingCount: len(cr.Findings),
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", c.cfg.APIURL+"/api/v1/hook/commit", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("User-Agent", "primust-hook/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return // Timeout or network error — silently ignore.
	}
	resp.Body.Close()
}

// FetchPolicy fetches the active policy from the API.
func (c *Client) FetchPolicy() ([]byte, error) {
	req, err := http.NewRequest("GET", c.cfg.APIURL+"/api/v1/policy/active", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("User-Agent", "primust-hook/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return buf.Bytes(), nil
}
