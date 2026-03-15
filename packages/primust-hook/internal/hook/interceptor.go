package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/primust-dev/primust-hook/internal/config"
	"github.com/primust-dev/primust-hook/internal/policy"
	"github.com/primust-dev/primust-hook/internal/transport"
)

// Action is the JSON payload from the IDE hook.
type Action struct {
	Tool   string `json:"tool"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// HookResult is the full result sent to the API and/or logged.
type HookResult struct {
	Timestamp      string        `json:"timestamp"`
	Tool           string        `json:"tool"`
	CommitmentHash string        `json:"commitment_hash"`
	CheckResults   []CheckResult `json:"check_results"`
	AllPassed      bool          `json:"all_passed"`
}

// Interceptor runs checks on IDE actions.
type Interceptor struct {
	policy *policy.Policy
	client *transport.Client
	cfg    *config.Config
}

// NewInterceptor creates a new interceptor with the given policy and transport.
func NewInterceptor(pol *policy.Policy, client *transport.Client, cfg *config.Config) *Interceptor {
	return &Interceptor{
		policy: pol,
		client: client,
		cfg:    cfg,
	}
}

// RunOnce reads a single action from stdin, runs checks, and writes results to stderr.
// NEVER blocks. Always returns (caller exits 0).
func (i *Interceptor) RunOnce(stdin io.Reader, stderr io.Writer) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "primust-hook: failed to read stdin: %v\n", err)
		return
	}

	if len(data) == 0 {
		return
	}

	var action Action
	if err := json.Unmarshal(data, &action); err != nil {
		fmt.Fprintf(stderr, "primust-hook: invalid JSON input: %v\n", err)
		return
	}

	result := i.processAction(&action)
	i.emitResult(result, stderr)
}

// RunDaemon reads actions line by line from stdin (newline-delimited JSON).
// Each action is processed independently. Never blocks.
func (i *Interceptor) RunDaemon(stdin io.Reader, stderr io.Writer) {
	decoder := json.NewDecoder(stdin)
	for {
		var action Action
		if err := decoder.Decode(&action); err != nil {
			if err == io.EOF {
				return
			}
			fmt.Fprintf(stderr, "primust-hook: decode error: %v\n", err)
			continue
		}
		result := i.processAction(&action)
		i.emitResult(result, stderr)
	}
}

func (i *Interceptor) processAction(action *Action) *HookResult {
	// Compute commitment hash (SHA-256 of tool + input + output).
	commitment := computeCommitment(action)

	// Combine input and output for scanning.
	content := action.Input + "\n" + action.Output

	// Run all enabled checks.
	var results []CheckResult
	allPassed := true
	for _, check := range i.policy.Checks {
		if !check.Enabled {
			continue
		}
		cr := RunCheck(check.Name, content, check.Threshold)
		results = append(results, cr)
		if !cr.Pass {
			allPassed = false
		}
	}

	hookResult := &HookResult{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Tool:           action.Tool,
		CommitmentHash: commitment,
		CheckResults:   results,
		AllPassed:      allPassed,
	}

	// Send to API (non-blocking — fire and forget on error).
	if !i.cfg.IsObservabilityOnly() {
		go i.client.SendCommitment(hookResult)
	}

	return hookResult
}

func (i *Interceptor) emitResult(result *HookResult, stderr io.Writer) {
	// Write structured JSON to stderr for IDE capture.
	data, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(stderr, "primust-hook: marshal error: %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "%s\n", data)

	// Also append to log file.
	i.appendLog(data)
}

func (i *Interceptor) appendLog(data []byte) {
	f, err := os.OpenFile(i.cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return // Silently ignore log errors — never block.
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
}

// computeCommitment produces a SHA-256 hash of the action's tool+input+output.
// This is the zero-content-transit commitment — only the hash leaves the machine.
func computeCommitment(action *Action) string {
	h := sha256.New()
	h.Write([]byte(action.Tool))
	h.Write([]byte("|"))
	h.Write([]byte(action.Input))
	h.Write([]byte("|"))
	h.Write([]byte(action.Output))
	return hex.EncodeToString(h.Sum(nil))
}
