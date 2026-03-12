package rulescore

import (
	"testing"
)

func TestCommit_Poseidon2_Empty(t *testing.T) {
	r := Commit([]byte{}, "poseidon2")
	expected := "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"
	if r.Hash != expected {
		t.Errorf("Commit(empty, poseidon2) = %s, want %s", r.Hash, expected)
	}
	if r.Algorithm != "poseidon2" {
		t.Errorf("Algorithm = %s, want poseidon2", r.Algorithm)
	}
}

func TestCommit_Poseidon2_Hello(t *testing.T) {
	r := Commit([]byte("hello"), "poseidon2")
	expected := "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960"
	if r.Hash != expected {
		t.Errorf("Commit(hello, poseidon2) = %s, want %s", r.Hash, expected)
	}
}

func TestCommit_SHA256_Hello(t *testing.T) {
	r := Commit([]byte("hello"), "sha256")
	expected := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if r.Hash != expected {
		t.Errorf("Commit(hello, sha256) = %s, want %s", r.Hash, expected)
	}
}

func TestCommitOutput_AlwaysPoseidon2(t *testing.T) {
	r := CommitOutput([]byte("test output"))
	if r.Algorithm != "poseidon2" {
		t.Errorf("CommitOutput algorithm = %s, want poseidon2", r.Algorithm)
	}
	if len(r.Hash) < 10 {
		t.Error("CommitOutput hash too short")
	}
}

func TestCommit_Deterministic(t *testing.T) {
	r1 := Commit([]byte("deterministic"), "poseidon2")
	r2 := Commit([]byte("deterministic"), "poseidon2")
	if r1.Hash != r2.Hash {
		t.Error("Commit should be deterministic")
	}
}

func TestCommit_CanonicalThenCommit(t *testing.T) {
	// Cross-language vector V9: canonical JSON → poseidon2
	input := map[string]interface{}{"entity": "Acme Corp", "type": "company"}
	jsonStr, err := Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON := `{"entity":"Acme Corp","type":"company"}`
	if jsonStr != expectedJSON {
		t.Errorf("Canonical = %s, want %s", jsonStr, expectedJSON)
	}

	r := Commit([]byte(jsonStr), "poseidon2")
	expected := "poseidon2:2b685b61654c85ab77d25d28d64bf007777cc0c8a15cdcc06ea1d16f362d8d87"
	if r.Hash != expected {
		t.Errorf("Commit(canonical) = %s, want %s", r.Hash, expected)
	}
}

func TestBuildCommitmentRoot_TwoHashes(t *testing.T) {
	h1 := "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"
	h2 := "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960"

	result := BuildCommitmentRoot([]string{h1, h2})
	if result == nil {
		t.Fatal("BuildCommitmentRoot returned nil")
	}
	expected := "poseidon2:0986c2eb74fa0774e9d04991e4e3853796d264478409cd94900b86c875732ef0"
	if *result != expected {
		t.Errorf("MerkleRoot(2) = %s, want %s", *result, expected)
	}
}

func TestBuildCommitmentRoot_ThreeHashes(t *testing.T) {
	h1 := "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"
	h2 := "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960"
	h3 := "poseidon2:287bf2eb6b6e174667ce2927eaefe1b151b758a8db683a43e41fb4f44c074b23"

	result := BuildCommitmentRoot([]string{h1, h2, h3})
	if result == nil {
		t.Fatal("BuildCommitmentRoot returned nil")
	}
	expected := "poseidon2:276d577a0c7471c9656aa4b3fb08eda71e5c66079085bc5993fa854ef06dfdce"
	if *result != expected {
		t.Errorf("MerkleRoot(3) = %s, want %s", *result, expected)
	}
}

func TestBuildCommitmentRoot_Empty(t *testing.T) {
	result := BuildCommitmentRoot([]string{})
	if result != nil {
		t.Error("BuildCommitmentRoot([]) should return nil")
	}
}

func TestBuildCommitmentRoot_Single(t *testing.T) {
	h := "poseidon2:abc123"
	result := BuildCommitmentRoot([]string{h})
	if result == nil || *result != h {
		t.Error("BuildCommitmentRoot([single]) should return that hash")
	}
}

func TestSelectProofLevel(t *testing.T) {
	tests := []struct {
		stageType string
		expected  string
	}{
		{"deterministic_rule", "mathematical"},
		{"policy_engine", "mathematical"},
		{"ml_model", "execution"},
		{"zkml_model", "execution_zkml"},
		{"statistical_test", "execution"},
		{"custom_code", "execution"},
		{"human_review", "witnessed"},
	}
	for _, tc := range tests {
		result, err := SelectProofLevel(tc.stageType)
		if err != nil {
			t.Errorf("SelectProofLevel(%s) error: %v", tc.stageType, err)
		}
		if result != tc.expected {
			t.Errorf("SelectProofLevel(%s) = %s, want %s", tc.stageType, result, tc.expected)
		}
	}
}

func TestSelectProofLevel_Unknown(t *testing.T) {
	_, err := SelectProofLevel("unknown")
	if err == nil {
		t.Error("SelectProofLevel(unknown) should return error")
	}
}
