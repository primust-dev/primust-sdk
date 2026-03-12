package rulescore

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// CommitmentResult holds a hash and the algorithm used.
type CommitmentResult struct {
	Hash      string
	Algorithm string
}

// Commit computes a commitment hash over input bytes.
// Algorithm must be "poseidon2" (default) or "sha256".
// Raw content NEVER leaves the customer environment — only the hash transits.
func Commit(data []byte, algorithm string) CommitmentResult {
	if algorithm == "sha256" {
		h := sha256.Sum256(data)
		return CommitmentResult{
			Hash:      "sha256:" + fmt.Sprintf("%064x", h),
			Algorithm: "sha256",
		}
	}
	return CommitmentResult{
		Hash:      Poseidon2Bytes(data),
		Algorithm: "poseidon2",
	}
}

// CommitOutput computes a commitment for check output. Always uses poseidon2.
func CommitOutput(data []byte) CommitmentResult {
	return CommitmentResult{
		Hash:      Poseidon2Bytes(data),
		Algorithm: "poseidon2",
	}
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
// Uses Poseidon2 for all intermediate nodes.
func BuildCommitmentRoot(hashes []string) *string {
	if len(hashes) == 0 {
		return nil
	}
	if len(hashes) == 1 {
		return &hashes[0]
	}

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

	hex := layer[0].Text(16)
	for len(hex) < 64 {
		hex = "0" + hex
	}
	result := "poseidon2:" + hex
	return &result
}

// SelectProofLevel selects the proof level for a given stage type.
// Returns an error for unknown stage types.
func SelectProofLevel(stageType string) (string, error) {
	switch stageType {
	case "deterministic_rule":
		return "mathematical", nil
	case "zkml_model":
		return "execution_zkml", nil
	case "ml_model":
		return "execution", nil
	case "statistical_test":
		return "execution", nil
	case "custom_code":
		return "execution", nil
	case "human_review":
		return "witnessed", nil
	case "policy_engine":
		return "mathematical", nil
	default:
		return "", fmt.Errorf("unknown stage type: %s", stageType)
	}
}
