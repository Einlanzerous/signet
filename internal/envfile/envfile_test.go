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
