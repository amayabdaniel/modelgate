package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// outputScannerSymbols are the public symbols of pkg/security/output.go
// that a response-path middleware would call to actually perform
// output scanning on an upstream model response. Keeping the list
// literal (not deriving it from AST reflection on pkg/security) means
// the test anchors on the specific symbols SECURITY.md advertises —
// a scanner function someone adds in the future gets added here AND
// to the SECURITY.md row's description, same commit.
var outputScannerSymbols = []string{
	"ScanOutput",
	"SanitizeOutput",
	"IsOutputClean",
	"RedactOutput",
	"ContainsSecrets",
	"MaskSecrets",
}

// outputScanningWiringMarkerRe matches the single-line marker placed
// in SECURITY.md next to the Defense-in-Depth list and the Data-
// exfiltration row. Values: scaffolded-only | wired-in-proxy.
// Whitespace tolerated around the colon.
var outputScanningWiringMarkerRe = regexp.MustCompile(
	`<!--\s*output-scanning-wiring:\s*(scaffolded-only|wired-in-proxy)\s*-->`,
)

// TestOutputScanningSecurityDocsMatchWiring is the 2026-11-23 drift
// guard for the SECURITY.md output-scanning correction. Prior to
// this commit the doc said LLM02 Insecure Output Handling was
// "Implemented — output scanning for PII, XSS, SQL injection,
// commands, secrets" and the Data exfiltration row was "Implemented",
// and the Defense in Depth list named output scanning as a shipping
// layer. In reality pkg/security/output.go had six public scanner
// functions, all unit-tested, with ZERO non-test callers in pkg/proxy
// — the proxy forwards model output unmodified. This test closes
// the drift in the direction (doc → code) that only an enumerating
// check catches: a caller-side wire-up (or its removal) must bump
// the marker.
//
// Two directions, both anchored:
//
//  1. CODE SIDE. Walk every non-_test.go file in this package, parse
//     with go/parser, visit every SelectorExpr whose Sel.Name is one
//     of outputScannerSymbols. Count calls. Today the count is 0.
//
//  2. DOC SIDE. Parse the marker value from SECURITY.md. Today the
//     value is "scaffolded-only".
//
// Assertion: count>0  ⇔  marker=="wired-in-proxy"; count==0  ⇔
// marker=="scaffolded-only". A missing marker fails with the exact
// line to add. A marker value that doesn't match the code count
// fails naming the mismatch and which side to update. Pattern-mates
// TestAuditActionsSyncedWithDocs in audit_action_docs_sync_test.go —
// that test closes the forward drift (code→docs) for AuditActions;
// this one closes the equivalent drift for output-scanning wiring,
// which is a yes/no capability rather than a value list.
//
// Silent-no-op floor: fail if zero .go files are scanned, or if
// outputScannerSymbols is empty. Either means the test was
// certifying nothing — the trap from feedback_verification_rigor.md.
func TestOutputScanningSecurityDocsMatchWiring(t *testing.T) {
	if len(outputScannerSymbols) == 0 {
		t.Fatal("outputScannerSymbols is empty — the test is certifying nothing; silent-no-op trap")
	}

	// 1. CODE SIDE: count callers in this package.
	wanted := make(map[string]bool, len(outputScannerSymbols))
	for _, s := range outputScannerSymbols {
		wanted[s] = true
	}

	scanned := 0
	var hits []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		scanned++

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !wanted[sel.Sel.Name] {
				return true
			}
			// Require the selector's receiver to be the identifier
			// `security` — this is the only import path under which
			// the scanner is reached, and pinning the receiver
			// avoids a chance collision with an unrelated local
			// method of the same name (e.g. a RedactOutput on some
			// other struct). If someone aliases the import, the
			// test will miss the wire-up on the alias; that's a
			// known false-negative — bump the marker manually in
			// that commit, same as any import rename.
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if recv.Name != "security" {
				return true
			}
			pos := fset.Position(sel.Pos())
			hits = append(hits, pos.Filename+":"+posString(pos.Line)+" security."+sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk pkg/proxy: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned zero non-_test .go files in pkg/proxy — the walker broke; silent-no-op trap")
	}
	codeWired := len(hits) > 0

	// 2. DOC SIDE: read the SECURITY.md marker.
	repoRoot := findRepoRoot(t)
	docPath := filepath.Join(repoRoot, "SECURITY.md")
	data, rerr := os.ReadFile(docPath)
	if rerr != nil {
		t.Fatalf("read %s: %v", docPath, rerr)
	}
	m := outputScanningWiringMarkerRe.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("SECURITY.md missing marker — add exactly one instance of\n  <!-- output-scanning-wiring: scaffolded-only -->\nor\n  <!-- output-scanning-wiring: wired-in-proxy -->\nnext to the Data exfiltration row so this test can validate it against the pkg/proxy wire-up state.", // nolint: this message is read by a human running the test
		)
	}
	marker := m[1]
	docWired := marker == "wired-in-proxy"

	if codeWired != docWired {
		if codeWired {
			t.Errorf("pkg/proxy wires output scanning (callers: %v) but SECURITY.md marker says %q. Flip the marker to `<!-- output-scanning-wiring: wired-in-proxy -->` AND change the Data exfiltration row's Status cell from \"Scaffolded, not wired\" to \"Implemented\" AND bump the OWASP LLM02 row's Coverage cell from \"Scaffolded, not wired\" to \"Implemented\" so the doc describes what ships.",
				hits, marker)
		} else {
			t.Errorf("SECURITY.md marker says %q (wired) but pkg/proxy has zero response-path callers of any of %v. Either wire a response-body middleware that calls one of those symbols on the upstream response before returning it (making the marker true), or flip the marker to `<!-- output-scanning-wiring: scaffolded-only -->` AND change the Status / Coverage cells to \"Scaffolded, not wired\" so the doc describes what actually ships.",
				marker, outputScannerSymbols)
		}
	}
}

// posString formats a line number without pulling in strconv for one
// call; keeps the import list focused on what the walk needs.
func posString(line int) string {
	if line == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for line > 0 {
		i--
		b[i] = byte('0' + line%10)
		line /= 10
	}
	return string(b[i:])
}
