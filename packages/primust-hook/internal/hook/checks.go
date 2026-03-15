package hook

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// CheckResult holds the outcome of a single check.
type CheckResult struct {
	Name    string   `json:"name"`
	Pass    bool     `json:"pass"`
	Findings []string `json:"findings,omitempty"`
}

// RunCheck dispatches to the appropriate built-in check by name.
func RunCheck(name string, content string, threshold float64) CheckResult {
	switch name {
	case "secrets_scanner":
		return checkSecrets(content)
	case "pii_regex":
		return checkPII(content)
	case "command_patterns":
		return checkCommandPatterns(content)
	case "cost_bounds":
		return checkCostBounds(content, threshold)
	default:
		return CheckResult{Name: name, Pass: true}
	}
}

// --- secrets_scanner ---

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*[A-Za-z0-9/+=]{40}`)},
	{"GitHub Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"GitHub OAuth", regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{"GitHub App Token", regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`)},
	{"GitHub App Install Token", regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`)},
	{"GitHub Refresh Token", regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`)},
	{"GCP API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|secret[_\-]?key)[\s]*[=:]\s*["']?[A-Za-z0-9]{32,}["']?`)},
}

func checkSecrets(content string) CheckResult {
	result := CheckResult{Name: "secrets_scanner", Pass: true}
	for _, sp := range secretPatterns {
		if matches := sp.pattern.FindAllString(content, 5); len(matches) > 0 {
			result.Pass = false
			for _, m := range matches {
				// Redact most of the match for safety.
				redacted := m
				if len(m) > 12 {
					redacted = m[:8] + "..." + m[len(m)-4:]
				}
				result.Findings = append(result.Findings, fmt.Sprintf("%s: %s", sp.name, redacted))
			}
		}
	}

	// High-entropy string detection (generic secrets).
	if findings := findHighEntropy(content); len(findings) > 0 {
		result.Pass = false
		result.Findings = append(result.Findings, findings...)
	}

	return result
}

// findHighEntropy looks for assignment-like patterns with high-entropy values.
func findHighEntropy(content string) []string {
	var findings []string
	// Look for quoted strings assigned to key/secret/token/password variables.
	re := regexp.MustCompile(`(?i)(?:password|secret|token|credential)[\s]*[=:]\s*["']([^"']{20,})["']`)
	for _, match := range re.FindAllStringSubmatch(content, 5) {
		if len(match) > 1 {
			entropy := shannonEntropy(match[1])
			if entropy > 4.0 {
				redacted := match[1][:6] + "..."
				findings = append(findings, fmt.Sprintf("high-entropy secret: %s (entropy=%.1f)", redacted, entropy))
			}
		}
	}
	return findings
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// --- pii_regex ---

var (
	ssnPattern    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccPattern     = regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`)
	emailPattern  = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	phonePattern  = regexp.MustCompile(`\b(?:\+?1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`)
)

func checkPII(content string) CheckResult {
	result := CheckResult{Name: "pii_regex", Pass: true}

	if matches := ssnPattern.FindAllString(content, 5); len(matches) > 0 {
		result.Pass = false
		for _, m := range matches {
			result.Findings = append(result.Findings, "SSN: ***-**-"+m[len(m)-4:])
		}
	}

	if matches := ccPattern.FindAllString(content, 5); len(matches) > 0 {
		for _, m := range matches {
			digits := extractDigits(m)
			if luhnValid(digits) {
				result.Pass = false
				result.Findings = append(result.Findings, "Credit Card: ****-****-****-"+digits[len(digits)-4:])
			}
		}
	}

	if matches := emailPattern.FindAllString(content, 5); len(matches) > 0 {
		result.Pass = false
		for _, m := range matches {
			result.Findings = append(result.Findings, "Email: "+m)
		}
	}

	if matches := phonePattern.FindAllString(content, 5); len(matches) > 0 {
		result.Pass = false
		for _, m := range matches {
			result.Findings = append(result.Findings, "Phone: "+m)
		}
	}

	return result
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if unicode.IsDigit(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func luhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// --- command_patterns ---

var dangerousPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"rm -rf", regexp.MustCompile(`\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\b`)},
	{"DROP TABLE", regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)},
	{"DROP DATABASE", regexp.MustCompile(`(?i)\bDROP\s+DATABASE\b`)},
	{"chmod 777", regexp.MustCompile(`\bchmod\s+777\b`)},
	{"curl|bash", regexp.MustCompile(`\bcurl\b.*\|\s*(bash|sh|zsh)\b`)},
	{"wget|bash", regexp.MustCompile(`\bwget\b.*\|\s*(bash|sh|zsh)\b`)},
	{"eval from variable", regexp.MustCompile(`\beval\s+\$`)},
	{"dd if=/dev", regexp.MustCompile(`\bdd\s+if=/dev/`)},
	{"mkfs", regexp.MustCompile(`\bmkfs\b`)},
	{"> /dev/sda", regexp.MustCompile(`>\s*/dev/[sh]d[a-z]`)},
}

func checkCommandPatterns(content string) CheckResult {
	result := CheckResult{Name: "command_patterns", Pass: true}
	for _, dp := range dangerousPatterns {
		if matches := dp.pattern.FindAllString(content, 3); len(matches) > 0 {
			result.Pass = false
			for _, m := range matches {
				result.Findings = append(result.Findings, fmt.Sprintf("%s: %s", dp.name, m))
			}
		}
	}
	return result
}

// --- cost_bounds ---

func checkCostBounds(content string, threshold float64) CheckResult {
	if threshold <= 0 {
		threshold = 100000 // default: ~100k tokens
	}
	// Rough token estimation: ~4 chars per token for English.
	estimatedTokens := float64(len(content)) / 4.0
	result := CheckResult{Name: "cost_bounds", Pass: true}
	if estimatedTokens > threshold {
		result.Pass = false
		result.Findings = append(result.Findings, fmt.Sprintf("estimated %.0f tokens exceeds threshold %.0f", estimatedTokens, threshold))
	}
	return result
}
