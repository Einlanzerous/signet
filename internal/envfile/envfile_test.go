package envfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseBasics(t *testing.T) {
	in := `
# comment line
FOO=bar

export BAZ=qux
QUOTED="hello world"
SINGLE='literal $VALUE'
ESCAPED="line1\nline2 \"quoted\" back\\slash"
EMPTY=
URL=postgres://user:p#ss@host:5432/db?sslmode=disable
DUP=first
DUP=second
`
	pairs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	m := Map(pairs)
	want := map[string]string{
		"FOO":     "bar",
		"BAZ":     "qux",
		"QUOTED":  "hello world",
		"SINGLE":  "literal $VALUE",
		"ESCAPED": "line1\nline2 \"quoted\" back\\slash",
		"EMPTY":   "",
		"URL":     "postgres://user:p#ss@host:5432/db?sslmode=disable",
		"DUP":     "second",
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("parse mismatch:\n got %#v\nwant %#v", m, want)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse(strings.NewReader("not a pair\n")); err == nil {
		t.Fatal("expected error for line without =")
	}
}

func TestParseMultilineQuoted(t *testing.T) {
	// A literal multi-line block (as hand-written .env files store PEM values)
	// plus a trailing key, to prove accumulation stops at the closing quote.
	// A CERTIFICATE marker with placeholder body — the parser keys off the
	// -----BEGIN/-----END markers, not the label, so this exercises the real
	// PEM path without embedding anything that looks like a private key.
	in := `KEY="-----BEGIN CERTIFICATE-----
body-line-one
body-line-two
-----END CERTIFICATE-----"
AFTER=sentinel
SINGLE='line one
line two'`
	pairs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	m := Map(pairs)
	wantPEM := "-----BEGIN CERTIFICATE-----\n" +
		"body-line-one\n" +
		"body-line-two\n" +
		"-----END CERTIFICATE-----"
	if m["KEY"] != wantPEM {
		t.Fatalf("multiline PEM mismatch:\n got %q\nwant %q", m["KEY"], wantPEM)
	}
	if m["AFTER"] != "sentinel" {
		t.Fatalf("key after multiline value not parsed: got %q", m["AFTER"])
	}
	if m["SINGLE"] != "line one\nline two" {
		t.Fatalf("single-quoted multiline mismatch: got %q", m["SINGLE"])
	}
}

func TestParseUnterminatedQuote(t *testing.T) {
	if _, err := Parse(strings.NewReader("KEY=\"unclosed\nstill going\n")); err == nil {
		t.Fatal("expected error for unterminated quoted value")
	}
}

func TestParseUnquotedPEM(t *testing.T) {
	// Raw unquoted PEM block (as some .env files store service-account keys),
	// with a following key to prove accumulation stops at -----END-----.
	// CERTIFICATE marker + placeholder body, per TestParseMultilineQuoted.
	in := `PRIVATE_KEY=-----BEGIN CERTIFICATE-----
body-line-one
body-line-two
-----END CERTIFICATE-----
AFTER=sentinel`
	pairs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	m := Map(pairs)
	wantPEM := "-----BEGIN CERTIFICATE-----\n" +
		"body-line-one\n" +
		"body-line-two\n" +
		"-----END CERTIFICATE-----"
	if m["PRIVATE_KEY"] != wantPEM {
		t.Fatalf("unquoted PEM mismatch:\n got %q\nwant %q", m["PRIVATE_KEY"], wantPEM)
	}
	if m["AFTER"] != "sentinel" {
		t.Fatalf("key after PEM not parsed: got %q", m["AFTER"])
	}
}

func TestParseUnterminatedPEM(t *testing.T) {
	in := "PRIVATE_KEY=-----BEGIN CERTIFICATE-----\nbody-line-one\n"
	if _, err := Parse(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for unterminated PEM block")
	}
}

func TestRenderParseRoundTrip(t *testing.T) {
	pairs := []Pair{
		{"ZED", "plain"},
		{"ALPHA", "has spaces"},
		{"HASH", "value#with#hash"},
		{"NEWLINE", "a\nb"},
		{"TAB", "a\tb"},
		{"QUOTE", `say "hi"`},
		{"BACKSLASH", `c:\path\to`},
		{"EMPTY", ""},
		{"SINGLEQ", "it's"},
	}
	rendered := Render(pairs)
	if !strings.HasPrefix(rendered, Header) {
		t.Fatal("missing managed header")
	}
	back, err := Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("re-parse: %v\nrendered:\n%s", err, rendered)
	}
	if !reflect.DeepEqual(Map(back), Map(pairs)) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v\nrendered:\n%s", Map(back), Map(pairs), rendered)
	}
	// Canonical render is sorted.
	keys := make([]string, len(back))
	for i, p := range back {
		keys[i] = p.Key
	}
	if !sortedStrings(keys) {
		t.Fatalf("render not sorted: %v", keys)
	}
}

// shaped is a hand-maintained file of the kind signet manages: a header, comment
// section titles, blank-line grouping, an "export " prefix, and a key someone
// added by hand that the vault does not know about.
const shaped = `# managed by signet — do not edit by hand

# Datadog
DD_API_KEY=old-dd-key
DD_SITE=datadoghq.com

# Semaphore UI
export SEMAPHORE_ADMIN=old-admin
UNMANAGED_TOKEN=hand-added-value

# trailing note
`

// managed is what the vault holds for shaped's target: one value changed, one
// unchanged, one key the file does not have yet. UNMANAGED_TOKEN is absent —
// that is the point.
var managed = []Pair{
	{"DD_API_KEY", "new-dd-key"},
	{"DD_SITE", "datadoghq.com"},
	{"SEMAPHORE_ADMIN", "rotated-admin"},
	{"NEW_KEY", "appended"},
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRenderIntoPreservesShape pins the whole contract in one comparison:
// managed values updated in place, everything else — comments, blank lines,
// ordering, the "export " prefix, the unmanaged key — exactly as it was found.
func TestRenderIntoPreservesShape(t *testing.T) {
	content, unmanaged, err := RenderInto(writeTemp(t, shaped), managed, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Header + `

# Datadog
DD_API_KEY=new-dd-key
DD_SITE=datadoghq.com

# Semaphore UI
export SEMAPHORE_ADMIN=rotated-admin
UNMANAGED_TOKEN=hand-added-value
NEW_KEY=appended

# trailing note
`
	if content != want {
		t.Fatalf("merge mismatch:\n got:\n%s\nwant:\n%s", content, want)
	}
	if !reflect.DeepEqual(unmanaged, []string{"UNMANAGED_TOKEN"}) {
		t.Fatalf("unmanaged keys: got %v, want [UNMANAGED_TOKEN]", unmanaged)
	}
}

// TestRenderIntoKeepsUnmanagedValues guards the specific loss the merge exists to
// prevent: a credential only the file has must still be readable afterwards, not
// merely present as a line.
func TestRenderIntoKeepsUnmanagedValues(t *testing.T) {
	content, _, err := RenderInto(writeTemp(t, shaped), managed, false)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if got := Map(back)["UNMANAGED_TOKEN"]; got != "hand-added-value" {
		t.Fatalf("unmanaged value lost: got %q", got)
	}
}

func TestRenderIntoPrune(t *testing.T) {
	content, unmanaged, err := RenderInto(writeTemp(t, shaped), managed, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "UNMANAGED_TOKEN") {
		t.Fatalf("--prune kept the unmanaged key:\n%s", content)
	}
	if !reflect.DeepEqual(unmanaged, []string{"UNMANAGED_TOKEN"}) {
		t.Fatalf("prune must report what it deleted: got %v", unmanaged)
	}
	// Pruning drops unmanaged keys, not the file's structure.
	for _, c := range []string{"# Datadog", "# Semaphore UI", "# trailing note"} {
		if !strings.Contains(content, c) {
			t.Fatalf("--prune dropped comment %q:\n%s", c, content)
		}
	}
}

// TestRenderIntoMissingFile covers the disaster-recovery case: nothing on disk
// to preserve, so the canonical render is what gets written.
func TestRenderIntoMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.env")
	content, unmanaged, err := RenderInto(path, managed, false)
	if err != nil {
		t.Fatal(err)
	}
	if content != Render(managed) {
		t.Fatalf("missing file should render canonically:\n%s", content)
	}
	if unmanaged != nil {
		t.Fatalf("no file means no unmanaged keys: got %v", unmanaged)
	}
}

// TestRenderIntoRefusesUnparseable: a file signet cannot read is a file it cannot
// merge into, and overwriting it would destroy exactly the content the parse
// failure says signet does not understand.
func TestRenderIntoRefusesUnparseable(t *testing.T) {
	path := writeTemp(t, "KEY=value\nthis line is not a pair\n")
	content, _, err := RenderInto(path, managed, false)
	if err == nil {
		t.Fatal("expected an error rather than a rewrite")
	}
	if content != "" {
		t.Fatalf("refused render must return no content, got:\n%s", content)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "KEY=value\nthis line is not a pair\n" {
		t.Fatalf("file was modified despite the refusal:\n%s", after)
	}
}

// TestRenderIntoHeaderHandling: a stale signet header is replaced so the file
// stops promising something render no longer does, but a file signet did not
// write does not acquire one.
func TestRenderIntoHeaderHandling(t *testing.T) {
	content, _, err := RenderInto(writeTemp(t, shaped), managed, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, Header+"\n") {
		t.Fatalf("stale header not refreshed:\n%s", content)
	}
	if strings.Contains(content, "do not edit by hand") {
		t.Fatalf("old header text survived:\n%s", content)
	}

	unheaded := writeTemp(t, "# my own notes\nDD_SITE=datadoghq.com\n")
	content, _, err = RenderInto(unheaded, []Pair{{"DD_SITE", "datadoghq.com"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if content != "# my own notes\nDD_SITE=datadoghq.com\n" {
		t.Fatalf("render added lines to a file it did not write:\n%s", content)
	}
}

// TestDocumentUntouchedIsVerbatim: parse-then-render with no edits reproduces the
// source byte for byte, including a multi-line PEM value.
func TestDocumentUntouchedIsVerbatim(t *testing.T) {
	in := `# note
  indented   =  spaced out
KEY="-----BEGIN CERTIFICATE-----
body-line-one
-----END CERTIFICATE-----"
export AFTER=sentinel
`
	doc, err := ParseDocument(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.String(); got != in {
		t.Fatalf("not verbatim:\n got:\n%s\nwant:\n%s", got, in)
	}
	// Editing a multi-line value collapses it to one quoted line, which has to
	// re-parse to the value that was set.
	doc.Set("KEY", "-----BEGIN CERTIFICATE-----\nrotated\n-----END CERTIFICATE-----")
	back, err := Parse(strings.NewReader(doc.String()))
	if err != nil {
		t.Fatalf("re-parse after edit: %v\n%s", err, doc.String())
	}
	m := Map(back)
	if m["KEY"] != "-----BEGIN CERTIFICATE-----\nrotated\n-----END CERTIFICATE-----" {
		t.Fatalf("edited multi-line value round-trip mismatch: got %q", m["KEY"])
	}
	if m["AFTER"] != "sentinel" || m["indented"] != "spaced out" {
		t.Fatalf("neighbouring entries disturbed by the edit: %#v", m)
	}
}

// TestSetKeepsNewKeysWithTheEntries: a key appended past the end lands under
// whatever trailing comment happens to be last, which reads as a claim about the
// key that signet has no basis for.
func TestSetKeepsNewKeysWithTheEntries(t *testing.T) {
	doc, err := ParseDocument(strings.NewReader("A=1\nB=2\n\n# a note about something else\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Set("C", "3")
	want := "A=1\nB=2\nC=3\n\n# a note about something else\n"
	if got := doc.String(); got != want {
		t.Fatalf("new key filed under the trailing comment:\n got:\n%s\nwant:\n%s", got, want)
	}
	// With no entries to sit beside there is nowhere better than the end.
	doc, err = ParseDocument(strings.NewReader("# just a note\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Set("A", "1")
	if got := doc.String(); got != "# just a note\nA=1\n" {
		t.Fatalf("comments-only document:\n%s", got)
	}
}

// TestMultilineValuesStayMultiline: collapsing a PEM to a backslash-escaped line
// is a format change on the values whose format is load bearing. Signet's parser
// reads "\n" back; `source .env` and compose's env_file do not.
func TestMultilineValuesStayMultiline(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nbody-line-one\nbody-line-two\n-----END CERTIFICATE-----"
	doc, err := ParseDocument(strings.NewReader("KEY=\"" + pem + "\"\nAFTER=sentinel\n"))
	if err != nil {
		t.Fatal(err)
	}
	rotated := strings.Replace(pem, "body-line-one", "body-rotated", 1)
	doc.Set("KEY", rotated)
	out := doc.String()
	if strings.Contains(out, `\n`) {
		t.Fatalf("rotation collapsed the block to an escaped line:\n%s", out)
	}
	if !strings.Contains(out, "\nbody-rotated\n") {
		t.Fatalf("rotated value is not a literal block:\n%s", out)
	}
	back, err := Parse(strings.NewReader(out))
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, out)
	}
	if m := Map(back); m["KEY"] != rotated || m["AFTER"] != "sentinel" {
		t.Fatalf("block did not round-trip: %#v", m)
	}
	// The canonical path writes the same shape, so a file recovered from scratch
	// is readable by the same consumers as one that was merged into.
	if strings.Contains(Render([]Pair{{"KEY", pem}}), `\n`) {
		t.Fatal("canonical render still collapses multi-line values")
	}
	// A value that cannot survive as a literal block — an embedded quote, a
	// line with meaningful leading space — falls back rather than corrupting.
	for _, v := range []string{"a\nsay \"hi\"", "a\n  indented", "a\nb\\c"} {
		if blockSafe(v) {
			t.Fatalf("blockSafe accepted a value it cannot round-trip: %q", v)
		}
		round, err := Parse(strings.NewReader("K=" + maybeQuote(v) + "\n"))
		if err != nil {
			t.Fatalf("fallback did not parse for %q: %v", v, err)
		}
		if got := Map(round)["K"]; got != v {
			t.Fatalf("fallback lossy for %q: got %q", v, got)
		}
	}
}

// TestRefreshHeaderRequiresAnExactMatch: a prefix match would let the one
// function whose job is not destroying hand-written lines destroy one.
func TestRefreshHeaderRequiresAnExactMatch(t *testing.T) {
	mine := "# managed by signet and by the deploy script — see the runbook before editing"
	content, _, err := RenderInto(writeTemp(t, mine+"\nDD_SITE=datadoghq.com\n"),
		[]Pair{{"DD_SITE", "datadoghq.com"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, mine+"\n") {
		t.Fatalf("hand-written line starting with the header words was overwritten:\n%s", content)
	}
}

// TestRenderIntoEmptyFile: an empty file has no more shape to preserve than a
// missing one, and the two recovery paths should not diverge.
func TestRenderIntoEmptyFile(t *testing.T) {
	for name, body := range map[string]string{"zero bytes": "", "blank lines": "\n\n  \n"} {
		content, unmanaged, err := RenderInto(writeTemp(t, body), managed, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if content != Render(managed) {
			t.Fatalf("%s: expected the canonical render, got:\n%s", name, content)
		}
		if unmanaged != nil {
			t.Fatalf("%s: unexpected unmanaged keys %v", name, unmanaged)
		}
	}
}

// TestRenderIntoMissingFileUnwraps pins the branch that stands between a live
// file and a canonical rewrite of it: it must not depend on the not-exist error
// arriving unwrapped from wherever it was raised.
func TestRenderIntoMissingFileUnwraps(t *testing.T) {
	_, err := ParseDocumentFile(filepath.Join(t.TempDir(), "absent.env"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file must report as fs.ErrNotExist through errors.Is, got %#v", err)
	}
	// A parse failure must not be mistaken for one, or an unreadable file would
	// be silently replaced by the canonical render instead of refused.
	if _, err := ParseDocumentFile(writeTemp(t, "not a pair\n")); errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("parse failure reported as not-exist: %v", err)
	}
}

// TestDocumentSetUpdatesEveryDuplicate: a dotenv reader keeps the last value, so
// leaving an earlier duplicate stale would make the file disagree with itself.
func TestDocumentSetUpdatesEveryDuplicate(t *testing.T) {
	doc, err := ParseDocument(strings.NewReader("DUP=first\nOTHER=x\nDUP=second\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Set("DUP", "third")
	if got := doc.String(); got != "DUP=third\nOTHER=x\nDUP=third\n" {
		t.Fatalf("duplicate not fully updated:\n%s", got)
	}
	if got := doc.Pairs(); !reflect.DeepEqual(got, []Pair{{"DUP", "third"}, {"OTHER", "x"}}) {
		t.Fatalf("pairs mismatch: %#v", got)
	}
}

func sortedStrings(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if xs[i-1] > xs[i] {
			return false
		}
	}
	return true
}
