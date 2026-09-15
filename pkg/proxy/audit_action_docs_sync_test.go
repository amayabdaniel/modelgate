package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestAuditActionsSyncedWithDocs prevents the drift described in
// AuditEvent's godoc DRIFT NOTE: the Action values live in code
// (AuditActions) and are also quoted in SECURITY.md and README.md.
// The prior form of SECURITY.md principle #5 became silently false
// when the guardrails fail-open default landed without anyone
// revisiting the doc — the same shape of gap this test closes.
//
// Two directions, both anchored so passing means something:
//
//  1. FORWARD (code → docs). For each value in AuditActions, the docs
//     must contain the exact literal string `"X"` (backtick-quoted
//     double-quoted), not just the bare word — a grep for the word
//     "allowed" would match prose anywhere and pass while proving
//     nothing. This anchors what "documented" means.
//
//  2. REVERSE (docs → code). Each doc carries a single-line HTML
//     comment marker
//
//     <!-- audit-action-values: allowed blocked passthrough -->
//
//     whose whitespace-separated value list must EQUAL AuditActions.
//     This is the direction a forward-only test would miss: a doc
//     that still advertises a value the code has removed (the case
//     when the multimodal parser eventually changes what
//     "passthrough" means and only two of the three descriptions are
//     updated) fails here.
//
// Both docs are required to declare the marker AND to contain the
// backticked+quoted mention of every AuditAction. A doc missing
// either fails with a message naming what to add.
func TestAuditActionsSyncedWithDocs(t *testing.T) {
	repoRoot := findRepoRoot(t)
	docs := []string{"SECURITY.md", "README.md"}

	// Marker regex: <!-- audit-action-values: a b c -->
	// Whitespace tolerated around the colon and the value list.
	markerRe := regexp.MustCompile(`<!--\s*audit-action-values:\s*(.+?)\s*-->`)

	for _, doc := range docs {
		doc := doc
		t.Run(doc, func(t *testing.T) {
			path := filepath.Join(repoRoot, doc)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			content := string(data)

			// FORWARD: each code-declared Action must appear as `"X"`
			// literally. Anchored form (backtick-quote-value-quote-
			// backtick) prevents accidental matches against prose.
			for _, action := range AuditActions {
				needle := "`\"" + action + "\"`"
				if !strings.Contains(content, needle) {
					t.Errorf("%s missing anchored mention of AuditAction %q — expected literal %s to appear somewhere in the doc so a reader linking the code value to the prose sees the exact string",
						doc, action, needle)
				}
			}

			// REVERSE: the marker must exist AND its value set must
			// equal AuditActions exactly (no extras, no missing).
			match := markerRe.FindStringSubmatch(content)
			if match == nil {
				t.Errorf("%s missing marker %q — add one instance of the marker so this test can validate the doc's Action-value list against code",
					doc, `<!-- audit-action-values: `+strings.Join(AuditActions, " ")+` -->`)
				return
			}
			declared := strings.Fields(match[1])
			sort.Strings(declared)
			want := append([]string(nil), AuditActions...)
			sort.Strings(want)
			if !equalStringSlices(declared, want) {
				t.Errorf("%s marker Action list drifted from code.\n  marker declares: %v\n  code declares:   %v\nThe code (AuditActions) is canonical — update the marker (and the surrounding prose) to match, or if you meant to remove an Action value from the code, also remove it from the marker AND its prose description.",
					doc, declared, want)
			}
		})
	}
}

// findRepoRoot walks up from this test file's directory until it finds
// go.mod, then returns that directory. Anchoring on runtime.Caller
// keeps the test working regardless of the caller's cwd (go test may
// run from anywhere, and IDE runners often set cwd to the repo root
// while `go test ./...` sets it to the package dir).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate test file")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find go.mod walking up from %s", filepath.Dir(thisFile))
	return ""
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
