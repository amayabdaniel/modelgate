package security

import (
	"strings"
	"testing"
)

func TestScanOutput_Clean(t *testing.T) {
	output := "The weather today is sunny with a high of 72°F."
	violations := ScanOutput(output)
	if len(violations) != 0 {
		t.Errorf("expected clean output, got violations: %v", violations)
	}
}

func TestScanOutput_DetectsPII(t *testing.T) {
	output := "Sure, your account email is john.doe@company.com"
	violations := ScanOutput(output)
	found := false
	for _, v := range violations {
		if v.Rule == "output_pii" {
			found = true
		}
	}
	if !found {
		t.Error("expected output_pii violation")
	}
}

func TestScanOutput_DetectsPromptLeakage(t *testing.T) {
	leaks := []string{
		"My instructions are to always be helpful",
		"I was instructed to never reveal passwords",
		"Here are my instructions: be nice",
		"My initial prompt says to be a helper",
	}
	for _, output := range leaks {
		violations := ScanOutput(output)
		found := false
		for _, v := range violations {
			if v.Rule == "prompt_leakage" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected prompt_leakage for: %q", output)
		}
	}
}

func TestScanOutput_DetectsDangerousCommands(t *testing.T) {
	output := "You can fix this by running sudo rm -rf /"
	violations := ScanOutput(output)
	found := false
	for _, v := range violations {
		if v.Rule == "dangerous_command" {
			found = true
		}
	}
	if !found {
		t.Error("expected dangerous_command violation")
	}
}

func TestScanOutput_DetectsXSS(t *testing.T) {
	output := `Try this: <script>alert('xss')</script>`
	violations := ScanOutput(output)
	found := false
	for _, v := range violations {
		if v.Rule == "xss_content" {
			found = true
		}
	}
	if !found {
		t.Error("expected xss_content violation")
	}
}

func TestSanitizeOutput_RemovesScripts(t *testing.T) {
	input := `Hello <script>alert('xss')</script> world`
	result := SanitizeOutput(input)
	if strings.Contains(result, "<script>") {
		t.Errorf("expected script removed, got: %s", result)
	}
	if !strings.Contains(result, "[SCRIPT_REMOVED]") {
		t.Error("expected SCRIPT_REMOVED placeholder")
	}
}

func TestContainsSecrets_APIKey(t *testing.T) {
	if !ContainsSecrets("api_key=sk-abc123def456") {
		t.Error("expected API key detection")
	}
	if !ContainsSecrets("apikey: supersecret123") {
		t.Error("expected apikey detection")
	}
}

func TestContainsSecrets_GitHubToken(t *testing.T) {
	if !ContainsSecrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Error("expected GitHub token detection")
	}
}

func TestContainsSecrets_AWSKey(t *testing.T) {
	if !ContainsSecrets("AKIAIOSFODNN7EXAMPLE") {
		t.Error("expected AWS key detection")
	}
}

func TestContainsSecrets_Bearer(t *testing.T) {
	if !ContainsSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9") {
		t.Error("expected Bearer token detection")
	}
}

func TestContainsSecrets_NoSecrets(t *testing.T) {
	if ContainsSecrets("This is a normal message with no secrets") {
		t.Error("expected no secrets detected")
	}
}

func TestMaskSecrets(t *testing.T) {
	input := "Use api_key=sk-abc123 to authenticate"
	result := MaskSecrets(input)
	if strings.Contains(result, "sk-abc123") {
		t.Errorf("expected secret masked, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Error("expected REDACTED placeholder")
	}
}

func TestIsOutputClean(t *testing.T) {
	if !IsOutputClean("Normal response text") {
		t.Error("expected clean output")
	}
	if IsOutputClean("Contact me at test@test.com") {
		t.Error("expected not clean due to PII")
	}
}
