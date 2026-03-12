package rulescore

import (
	"testing"
)

func TestCanonical_SimpleObject(t *testing.T) {
	// Cross-language vector V5: {"b": 1, "a": 2} → {"a":2,"b":1}
	input := map[string]interface{}{"b": 1, "a": 2}
	result, err := Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":2,"b":1}`
	if result != expected {
		t.Errorf("Canonical({b:1,a:2}) = %s, want %s", result, expected)
	}
}

func TestCanonical_NestedObject(t *testing.T) {
	// Cross-language vector V6: {"z": [1, {"b": 2, "a": 1}], "a": "x"}
	input := map[string]interface{}{
		"z": []interface{}{1, map[string]interface{}{"b": 2, "a": 1}},
		"a": "x",
	}
	result, err := Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":"x","z":[1,{"a":1,"b":2}]}`
	if result != expected {
		t.Errorf("Canonical(nested) = %s, want %s", result, expected)
	}
}

func TestCanonical_EmptyObject(t *testing.T) {
	// Cross-language vector V7
	result, err := Canonical(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result != "{}" {
		t.Errorf("Canonical({}) = %s, want {}", result)
	}
}

func TestCanonical_ArrayPreservesOrder(t *testing.T) {
	// Cross-language vector V8: [3, 1, 2] → [3,1,2] (NOT sorted)
	result, err := Canonical([]interface{}{3, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if result != "[3,1,2]" {
		t.Errorf("Canonical([3,1,2]) = %s, want [3,1,2]", result)
	}
}

func TestCanonical_Null(t *testing.T) {
	result, err := Canonical(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != "null" {
		t.Errorf("Canonical(nil) = %s, want null", result)
	}
}

func TestCanonical_Boolean(t *testing.T) {
	r1, _ := Canonical(true)
	r2, _ := Canonical(false)
	if r1 != "true" {
		t.Errorf("Canonical(true) = %s", r1)
	}
	if r2 != "false" {
		t.Errorf("Canonical(false) = %s", r2)
	}
}

func TestCanonical_String(t *testing.T) {
	result, err := Canonical("hello")
	if err != nil {
		t.Fatal(err)
	}
	if result != `"hello"` {
		t.Errorf("Canonical(hello) = %s", result)
	}
}

func TestCanonical_NoWhitespace(t *testing.T) {
	input := map[string]interface{}{
		"key": []interface{}{1, 2, map[string]interface{}{"nested": true}},
	}
	result, err := Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	// No spaces or newlines
	expected := `{"key":[1,2,{"nested":true}]}`
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}
