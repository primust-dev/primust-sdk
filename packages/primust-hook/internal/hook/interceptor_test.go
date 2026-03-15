package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/primust-dev/primust-hook/internal/config"
	"github.com/primust-dev/primust-hook/internal/policy"
	"github.com/primust-dev/primust-hook/internal/transport"
)

func newTestInterceptor() *Interceptor {
	cfg := &config.Config{
		APIURL:  "https://api.primust.com",
		LogPath: "/dev/null",
	}
	pol := policy.EmptyPolicy()
	client := transport.NewClient(cfg)
	return NewInterceptor(pol, client, cfg)
}

func TestRunOnce_ValidAction(t *testing.T) {
	interceptor := newTestInterceptor()
	action := Action{
		Tool:   "bash",
		Input:  "echo hello",
		Output: "hello",
	}
	data, _ := json.Marshal(action)
	stdin := bytes.NewReader(data)
	stderr := &bytes.Buffer{}

	interceptor.RunOnce(stdin, stderr)

	if stderr.Len() == 0 {
		t.Error("expected output on stderr")
	}

	// Parse the result from stderr.
	var result HookResult
	if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse stderr output: %v", err)
	}

	if result.Tool != "bash" {
		t.Errorf("expected tool=bash, got %s", result.Tool)
	}
	if result.CommitmentHash == "" {
		t.Error("expected non-empty commitment hash")
	}
	if !result.AllPassed {
		t.Error("expected all checks to pass for clean input")
	}
}

func TestRunOnce_WithSecrets(t *testing.T) {
	interceptor := newTestInterceptor()
	action := Action{
		Tool:   "write_file",
		Input:  `{"path": "config.py", "content": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"}`,
		Output: "file written",
	}
	data, _ := json.Marshal(action)
	stdin := bytes.NewReader(data)
	stderr := &bytes.Buffer{}

	interceptor.RunOnce(stdin, stderr)

	var result HookResult
	if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse stderr output: %v", err)
	}

	if result.AllPassed {
		t.Error("expected checks to fail for content with secrets")
	}

	// Verify secrets_scanner failed.
	found := false
	for _, cr := range result.CheckResults {
		if cr.Name == "secrets_scanner" && !cr.Pass {
			found = true
		}
	}
	if !found {
		t.Error("expected secrets_scanner check to fail")
	}
}

func TestRunOnce_EmptyInput(t *testing.T) {
	interceptor := newTestInterceptor()
	stdin := bytes.NewReader([]byte{})
	stderr := &bytes.Buffer{}

	interceptor.RunOnce(stdin, stderr)

	// Should produce no output for empty input.
	if stderr.Len() != 0 {
		t.Errorf("expected no output for empty input, got: %s", stderr.String())
	}
}

func TestRunOnce_InvalidJSON(t *testing.T) {
	interceptor := newTestInterceptor()
	stdin := bytes.NewReader([]byte("not json"))
	stderr := &bytes.Buffer{}

	interceptor.RunOnce(stdin, stderr)

	output := stderr.String()
	if !strings.Contains(output, "invalid JSON") {
		t.Errorf("expected invalid JSON error, got: %s", output)
	}
}

func TestComputeCommitment_Deterministic(t *testing.T) {
	action := &Action{Tool: "bash", Input: "ls", Output: "file.txt"}
	hash1 := computeCommitment(action)
	hash2 := computeCommitment(action)
	if hash1 != hash2 {
		t.Error("commitment hash should be deterministic")
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64 char hex hash, got %d chars", len(hash1))
	}
}

func TestComputeCommitment_DifferentInputs(t *testing.T) {
	a1 := &Action{Tool: "bash", Input: "ls", Output: "file.txt"}
	a2 := &Action{Tool: "bash", Input: "pwd", Output: "/home"}
	if computeCommitment(a1) == computeCommitment(a2) {
		t.Error("different actions should produce different commitment hashes")
	}
}

func TestRunDaemon_MultipleActions(t *testing.T) {
	interceptor := newTestInterceptor()

	actions := []Action{
		{Tool: "bash", Input: "echo 1", Output: "1"},
		{Tool: "bash", Input: "echo 2", Output: "2"},
	}

	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, a := range actions {
		enc.Encode(a)
	}

	stderr := &bytes.Buffer{}
	interceptor.RunDaemon(&input, stderr)

	// Should have two results.
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 result lines, got %d: %s", len(lines), stderr.String())
	}
}
