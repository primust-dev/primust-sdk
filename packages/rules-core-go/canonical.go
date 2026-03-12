package rulescore

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Canonical produces deterministic JSON output with recursively sorted keys
// and no whitespace. Two structurally identical objects always produce the
// same string regardless of key insertion order.
//
// Rules:
//   - Object keys sorted lexicographically at every nesting depth
//   - Array element order preserved (never sorted)
//   - No whitespace
//   - Only JSON-native types: string, float64, int/int64, bool, nil, map[string]interface{}, []interface{}
func Canonical(value interface{}) (string, error) {
	return serializeValue(value)
}

func serializeValue(value interface{}) (string, error) {
	if value == nil {
		return "null", nil
	}

	switch v := value.(type) {
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil

	case int:
		return strconv.Itoa(v), nil

	case int64:
		return strconv.FormatInt(v, 10), nil

	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", fmt.Errorf("canonical: cannot serialize %v (NaN/Infinity are not valid JSON)", v)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case map[string]interface{}:
		return serializeObject(v)

	case []interface{}:
		return serializeArray(v)

	default:
		return "", fmt.Errorf("canonical: unsupported type %T", value)
	}
}

func serializeObject(obj map[string]interface{}) (string, error) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	for _, key := range keys {
		val := obj[key]
		serializedVal, err := serializeValue(val)
		if err != nil {
			return "", err
		}
		serializedKey, err := json.Marshal(key)
		if err != nil {
			return "", err
		}
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.Write(serializedKey)
		sb.WriteByte(':')
		sb.WriteString(serializedVal)
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

func serializeArray(arr []interface{}) (string, error) {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			sb.WriteByte(',')
		}
		s, err := serializeValue(item)
		if err != nil {
			return "", err
		}
		sb.WriteString(s)
	}
	sb.WriteByte(']')
	return sb.String(), nil
}
