package security

import (
	"regexp"
	"strings"
)

// OutputViolation represents a security issue found in model output.
type OutputViolation struct {
	Rule     string
	Severity string
	Message  string
}

// ScanOutput checks model response text for security issues.
// Detects: PII leakage, prompt leakage, and dangerous content.
func ScanOutput(output string) []OutputViolation {
	var violations []OutputViolation

	// Check for PII in output
	if ContainsPII(output) {
		violations = append(violations, OutputViolation{
			Rule:     "output_pii",
			Severity: "critical",
			Message:  "Model output contains PII",
		})
	}

	// Check for system prompt leakage patterns
	promptLeakagePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)my\s+(system\s+)?instructions?\s+(are|say|tell)`),
		regexp.MustCompile(`(?i)i\s+was\s+(told|instructed|programmed)\s+to`),
		regexp.MustCompile(`(?i)my\s+initial\s+prompt`),
		regexp.MustCompile(`(?i)here\s+(is|are)\s+my\s+instructions?`),
	}
	for _, re := range promptLeakagePatterns {
		if re.MatchString(output) {
			violations = append(violations, OutputViolation{
				Rule:     "prompt_leakage",
				Severity: "warning",
				Message:  "Model output may contain system prompt leakage",
			})
			break
		}
	}

	// Check for dangerous content patterns
	dangerousPatterns := map[string]string{
		`(?i)(sudo|chmod\s+777|rm\s+-rf\s+/)`:                   "dangerous_command",
		`(?i)(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE)`:              "sql_injection",
		`(?i)(<script|javascript:|on\w+\s*=)`:                    "xss_content",
	}
	for pattern, rule := range dangerousPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(output) {
			violations = append(violations, OutputViolation{
				Rule:     rule,
				Severity: "warning",
				Message:  "Model output contains potentially dangerous content: " + rule,
			})
		}
	}

	return violations
}

// SanitizeOutput applies redaction to model output.
func SanitizeOutput(output string) string {
	result := RedactPII(output)

	// Strip potential script tags
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`)
	result = scriptRe.ReplaceAllString(result, "[SCRIPT_REMOVED]")

	// Strip event handlers
	eventRe := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*["'][^"']*["']`)
	result = eventRe.ReplaceAllString(result, "")

	return result
}

// IsOutputClean returns true if the output passes all security checks.
func IsOutputClean(output string) bool {
	return len(ScanOutput(output)) == 0
}

// RedactOutput redacts PII and returns both the clean output and whether changes were made.
func RedactOutput(output string) (string, bool) {
	redacted := RedactPII(output)
	changed := redacted != output
	return redacted, changed
}

// ContainsSecrets checks for common secret patterns in output.
func ContainsSecrets(text string) bool {
	secretPatterns := []string{
		`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`,
		`(?i)(secret|password|passwd|pwd)\s*[=:]\s*\S+`,
		`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`,
		`(?i)ghp_[A-Za-z0-9]{36}`,
		`(?i)sk-[A-Za-z0-9]{48}`,
		`AKIA[0-9A-Z]{16}`,
	}

	for _, pattern := range secretPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(text) {
			return true
		}
	}

	return false
}

// MaskSecrets replaces detected secrets with placeholders.
func MaskSecrets(text string) string {
	replacements := map[string]string{
		`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`:     "$1=[REDACTED]",
		`(?i)(secret|password|passwd|pwd)\s*[=:]\s*\S+`: "$1=[REDACTED]",
		`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`:      "${1}[REDACTED]",
		`(?i)ghp_[A-Za-z0-9]{36}`:                    "[GITHUB_TOKEN_REDACTED]",
		`(?i)sk-[A-Za-z0-9]{48}`:                     "[OPENAI_KEY_REDACTED]",
		`AKIA[0-9A-Z]{16}`:                           "[AWS_KEY_REDACTED]",
	}

	result := text
	for pattern, replacement := range replacements {
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllString(result, replacement)
	}
	return result
}

// placeholder to avoid unused import
var _ = strings.Contains
