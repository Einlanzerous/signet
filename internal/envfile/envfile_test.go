package envfile

import (
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

func sortedStrings(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if xs[i-1] > xs[i] {
			return false
		}
	}
	return true
}
