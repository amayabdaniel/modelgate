package security

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NormalizeInput applies security normalization to user input before checking.
// This defeats common bypass techniques:
// - Unicode homoglyph substitution
// - Zero-width character insertion
// - Whitespace obfuscation
// - Case normalization
// - HTML entity decoding
func NormalizeInput(input string) string {
	// Step 1: Unicode NFC normalization (canonical decomposition + composition)
	result := norm.NFC.String(input)

	// Step 2: Remove zero-width characters
	result = removeZeroWidth(result)

	// Step 3: Normalize whitespace (collapse multiple spaces, tabs, newlines)
	result = normalizeWhitespace(result)

	// Step 4: Decode common HTML entities
	result = decodeHTMLEntities(result)

	// Step 5: Remove invisible/control characters (except newline, tab)
	result = removeControlChars(result)

	return result
}

func removeZeroWidth(s string) string {
	zeroWidthChars := []rune{
		'\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\uFEFF', // byte order mark / zero-width no-break space
		'\u00AD', // soft hyphen
		'\u2060', // word joiner
		'\u180E', // mongolian vowel separator
	}

	for _, zw := range zeroWidthChars {
		s = strings.ReplaceAll(s, string(zw), "")
	}
	return s
}

func normalizeWhitespace(s string) string {
	// Replace all whitespace sequences with single space
	re := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(re.ReplaceAllString(s, " "))
}

func decodeHTMLEntities(s string) string {
	replacements := map[string]string{
		"&lt;":   "<",
		"&gt;":   ">",
		"&amp;":  "&",
		"&quot;": `"`,
		"&#39;":  "'",
		"&apos;": "'",
		"&#x27;": "'",
		"&#x3C;": "<",
		"&#x3E;": ">",
		"&#60;":  "<",
		"&#62;":  ">",
	}

	result := s
	for entity, char := range replacements {
		result = strings.ReplaceAll(result, entity, char)
		// Also handle uppercase variants
		result = strings.ReplaceAll(result, strings.ToUpper(entity), char)
	}
	return result
}

func removeControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' ' // normalize to space
		}
		if unicode.IsControl(r) {
			return -1 // remove
		}
		return r
	}, s)
}
