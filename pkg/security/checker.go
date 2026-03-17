package security

import (
	"regexp"
	"strings"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
)

// Violation represents a security check failure.
type Violation struct {
	Rule     string
	Severity string
	Message  string
	Position int // character position in prompt where violation was found, -1 if N/A
}

// PromptChecker evaluates prompts against an InferencePolicy security spec.
type PromptChecker struct {
	policy           v1alpha1.SecurityPolicy
	blockedRegexes   []*regexp.Regexp
	injectionPatterns []*regexp.Regexp
}

// Common prompt injection patterns.
var defaultInjectionPatterns = []string{
	`(?i)ignore\s+(all\s+)?previous\s+instructions`,
	`(?i)ignore\s+(all\s+)?above\s+instructions`,
	`(?i)disregard\s+(all\s+)?previous`,
	`(?i)forget\s+(all\s+)?(your\s+)?instructions`,
	`(?i)you\s+are\s+now\s+(a|an)\s+`,
	`(?i)new\s+instructions?\s*:`,
	`(?i)system\s*prompt\s*:`,
	`(?i)reveal\s+(your\s+)?(system\s+)?prompt`,
	`(?i)print\s+(your\s+)?(system\s+)?prompt`,
	`(?i)show\s+(me\s+)?(your\s+)?(system\s+)?prompt`,
	`(?i)\bDAN\b.*\bjailbreak\b`,
	`(?i)do\s+anything\s+now`,
	`(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions`,
}

// NewPromptChecker creates a checker from a security policy.
func NewPromptChecker(policy v1alpha1.SecurityPolicy) (*PromptChecker, error) {
	pc := &PromptChecker{policy: policy}

	for _, pattern := range policy.BlockedPatterns {
		re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pattern))
		if err != nil {
			return nil, err
		}
		pc.blockedRegexes = append(pc.blockedRegexes, re)
	}

	if policy.PromptInjectionProtection {
		for _, pattern := range defaultInjectionPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			pc.injectionPatterns = append(pc.injectionPatterns, re)
		}
	}

	return pc, nil
}

// Check evaluates a prompt against all security rules and returns violations.
func (pc *PromptChecker) Check(prompt string) []Violation {
	var violations []Violation

	// Check blocked patterns
	for _, re := range pc.blockedRegexes {
		loc := re.FindStringIndex(prompt)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "blocked_pattern",
				Severity: "critical",
				Message:  "Prompt contains blocked pattern: " + re.String(),
				Position: loc[0],
			})
		}
	}

	// Check prompt injection patterns
	for _, re := range pc.injectionPatterns {
		loc := re.FindStringIndex(prompt)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "prompt_injection",
				Severity: "critical",
				Message:  "Potential prompt injection detected",
				Position: loc[0],
			})
		}
	}

	// Check max prompt tokens (rough estimate: 1 token ≈ 4 chars)
	if pc.policy.MaxPromptTokens > 0 {
		estimatedTokens := len(prompt) / 4
		if estimatedTokens > pc.policy.MaxPromptTokens {
			violations = append(violations, Violation{
				Rule:     "max_tokens",
				Severity: "warning",
				Message:  "Prompt exceeds estimated token limit",
				Position: -1,
			})
		}
	}

	return violations
}

// IsClean returns true if the prompt passes all security checks.
func (pc *PromptChecker) IsClean(prompt string) bool {
	return len(pc.Check(prompt)) == 0
}

// RedactPII performs basic PII redaction on model output.
// Replaces common patterns: emails, phone numbers, SSNs, credit cards.
func RedactPII(text string) string {
	patterns := map[string]string{
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`:        "[EMAIL_REDACTED]",
		`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`:                                "[PHONE_REDACTED]",
		`\b\d{3}-\d{2}-\d{4}\b`:                                        "[SSN_REDACTED]",
		`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`:                  "[CC_REDACTED]",
	}

	result := text
	for pattern, replacement := range patterns {
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllString(result, replacement)
	}

	return result
}

// ContainsPII checks if text contains potential PII.
func ContainsPII(text string) bool {
	return strings.Contains(RedactPII(text), "_REDACTED]")
}
