package rulescore

import (
	"math/big"
	"testing"
)

func TestHash_SingleElement(t *testing.T) {
	// Cross-language vector: poseidon2_hash([42]) from Python
	result := Hash([]*big.Int{big.NewInt(42)})
	expected, _ := new(big.Int).SetString("16903261348599640072149966459073306148075553566572715541601812593675317705224", 10)
	if result.Cmp(expected) != 0 {
		t.Errorf("Hash([42]) = %s, want %s", result.String(), expected.String())
	}
}

func TestHash_TwoElements(t *testing.T) {
	// Cross-language vector: poseidon2_hash([1, 2]) from Python
	result := Hash([]*big.Int{big.NewInt(1), big.NewInt(2)})
	expected, _ := new(big.Int).SetString("1594597865669602199208529098208508950092942746041644072252494753744672355203", 10)
	if result.Cmp(expected) != 0 {
		t.Errorf("Hash([1,2]) = %s, want %s", result.String(), expected.String())
	}
}

func TestPoseidon2Bytes_Empty(t *testing.T) {
	// Cross-language vector: commit(b"", "poseidon2") from Python
	result := Poseidon2Bytes([]byte{})
	expected := "poseidon2:0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"
	if result != expected {
		t.Errorf("Poseidon2Bytes(empty) = %s, want %s", result, expected)
	}
}

func TestPoseidon2Bytes_Hello(t *testing.T) {
	// Cross-language vector: commit(b"hello", "poseidon2") from Python
	result := Poseidon2Bytes([]byte("hello"))
	expected := "poseidon2:2c9c245e34a2bbbdc320d92f1df0e5e435de6a991a80bf9b90d908bc8b8a1960"
	if result != expected {
		t.Errorf("Poseidon2Bytes(hello) = %s, want %s", result, expected)
	}
}

func TestPoseidon2Bytes_LongInput(t *testing.T) {
	// Cross-language vector: crosses 31-byte boundary
	result := Poseidon2Bytes([]byte("The quick brown fox jumps over the lazy dog"))
	expected := "poseidon2:287bf2eb6b6e174667ce2927eaefe1b151b758a8db683a43e41fb4f44c074b23"
	if result != expected {
		t.Errorf("Poseidon2Bytes(long) = %s, want %s", result, expected)
	}
}

func TestBytesToFieldElements_ChunkSize(t *testing.T) {
	// 31 bytes should produce exactly 1 element
	data := make([]byte, 31)
	for i := range data {
		data[i] = byte(i)
	}
	elements := BytesToFieldElements(data)
	if len(elements) != 1 {
		t.Errorf("31 bytes should produce 1 element, got %d", len(elements))
	}

	// 32 bytes should produce 2 elements
	data2 := make([]byte, 32)
	for i := range data2 {
		data2[i] = byte(i)
	}
	elements2 := BytesToFieldElements(data2)
	if len(elements2) != 2 {
		t.Errorf("32 bytes should produce 2 elements, got %d", len(elements2))
	}
}
