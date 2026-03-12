package rulescore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// CommitmentResult holds a hash and the algorithm used.
type CommitmentResult struct {
	Hash      string
	Algorithm string
}

// ResolveAlgorithm returns the commitment algorithm to use.
// Checks PRIMUST_COMMITMENT_ALGORITHM env var, defaults to "sha256".
// Poseidon2 is opt-in until an audited implementation (e.g. Barretenberg) is validated.
func ResolveAlgorithm() string {
	if alg := os.Getenv("PRIMUST_COMMITMENT_ALGORITHM"); alg == "poseidon2" {
		return "poseidon2"
	}
	return "sha256"
}

// Commit computes a commitment hash over input bytes.
// Algorithm must be "sha256" (default) or "poseidon2".
// Raw content NEVER leaves the customer environment — only the hash transits.
func Commit(data []byte, algorithm string) CommitmentResult {
	if algorithm == "poseidon2" {
		return CommitmentResult{
			Hash:      Poseidon2Bytes(data),
			Algorithm: "poseidon2",
		}
	}
	h := sha256.Sum256(data)
	return CommitmentResult{
		Hash:      "sha256:" + fmt.Sprintf("%064x", h),
		Algorithm: "sha256",
	}
}

// CommitDefault computes a commitment using the resolved algorithm (env var or sha256 default).
func CommitDefault(data []byte) CommitmentResult {
	return Commit(data, ResolveAlgorithm())
}

// CommitOutput computes a commitment for check output. Uses the resolved algorithm.
func CommitOutput(data []byte) CommitmentResult {
	return Commit(data, ResolveAlgorithm())
}

// parseHashToField parses an "algorithm:hex" hash string to a field element.
func parseHashToField(hash string) (*big.Int, error) {
	idx := strings.Index(hash, ":")
	if idx == -1 {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	hexStr := hash[idx+1:]
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex in hash: %s", hexStr)
	}
	v.Mod(v, BN254P)
	return v, nil
}

// BuildCommitmentRoot builds a Merkle root over an array of commitment hashes.
// Returns nil for empty input. Single hash returns unchanged.
// Uses the resolved algorithm (SHA-256 default, Poseidon2 opt-in) for intermediate nodes.
func BuildCommitmentRoot(hashes []string) *string {
	return BuildCommitmentRootWithAlgorithm(hashes, ResolveAlgorithm())
}

// BuildCommitmentRootWithAlgorithm builds a Merkle root using the specified algorithm
// for intermediate nodes.
func BuildCommitmentRootWithAlgorithm(hashes []string, algorithm string) *string {
	if len(hashes) == 0 {
		return nil
	}
	if len(hashes) == 1 {
		return &hashes[0]
	}

	if algorithm == "poseidon2" {
		return buildPoseidon2MerkleRoot(hashes)
	}
	return buildSha256MerkleRoot(hashes)
}

func buildPoseidon2MerkleRoot(hashes []string) *string {
	layer := make([]*big.Int, len(hashes))
	for i, h := range hashes {
		v, err := parseHashToField(h)
		if err != nil {
			return nil
		}
		layer[i] = v
	}

	for len(layer) > 1 {
		var next []*big.Int
		for i := 0; i < len(layer); i += 2 {
			left := layer[i]
			right := left
			if i+1 < len(layer) {
				right = layer[i+1]
			}
			next = append(next, Hash([]*big.Int{left, right}))
		}
		layer = next
	}

	h := layer[0].Text(16)
	for len(h) < 64 {
		h = "0" + h
	}
	result := "poseidon2:" + h
	return &result
}

func buildSha256MerkleRoot(hashes []string) *string {
	layer := make([][]byte, len(hashes))
	for i, h := range hashes {
		raw, err := parseHashToRawBytes(h)
		if err != nil {
			return nil
		}
		layer[i] = raw
	}

	for len(layer) > 1 {
		var next [][]byte
		for i := 0; i < len(layer); i += 2 {
			left := layer[i]
			right := left
			if i+1 < len(layer) {
				right = layer[i+1]
			}
			combined := make([]byte, len(left)+len(right))
			copy(combined, left)
			copy(combined[len(left):], right)
			h := sha256.Sum256(combined)
			next = append(next, h[:])
		}
		layer = next
	}

	result := "sha256:" + hex.EncodeToString(layer[0])
	return &result
}

// parseHashToRawBytes parses "algorithm:hex" to raw bytes.
func parseHashToRawBytes(hash string) ([]byte, error) {
	idx := strings.Index(hash, ":")
	if idx == -1 {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	return hex.DecodeString(hash[idx+1:])
}

// SelectProofLevel selects the proof level for a given stage type.
// Returns an error for unknown stage types.
func SelectProofLevel(stageType string) (string, error) {
	switch stageType {
	case "deterministic_rule":
		return "mathematical", nil
	case "zkml_model":
		return "verifiable_inference", nil
	case "ml_model":
		return "execution", nil
	case "statistical_test":
		return "execution", nil
	case "custom_code":
		return "execution", nil
	case "witnessed":
		return "witnessed", nil
	case "policy_engine":
		return "mathematical", nil
	default:
		return "", fmt.Errorf("unknown stage type: %s", stageType)
	}
}
