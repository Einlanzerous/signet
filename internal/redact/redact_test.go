package redact

import (
	"bytes"
	"strings"
	"testing"
)

func filterOf(values ...Value) *Filter { return New(values) }

// run writes the chunks through a filter and returns what reached the sink.
// Chunking is a parameter because it is the property under test: a pipe hands
// a value over in whatever pieces the kernel felt like, and a filter that only
// works when a token arrives whole is a filter that works in tests and not in
// production.
func run(t *testing.T, f *Filter, chunks ...string) string {
	t.Helper()
	var sink bytes.Buffer
	w := f.Writer(&sink)
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return sink.String()
}

func TestReplacesAValueInOnePiece(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	got := run(t, f, "Authorization: Bearer s3cret-token-value\n")
	want := "Authorization: Bearer «redacted:csrv/TOKEN»\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The case the type exists for. A 40-character token arriving as 30 bytes and
// then 10 is not an edge case — it is what a pipe does — and a filter that
// matched only within a single Write would pass the obvious test and leak in
// production.
func TestReplacesAValueSplitAcrossWrites(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	got := run(t, f, "Bearer s3cret-", "token-", "value done\n")
	want := "Bearer «redacted:csrv/TOKEN» done\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Split one byte at a time — the worst case, and the one that catches a
// holdback boundary that is off by one.
func TestReplacesAValueSplitByteByByte(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	var chunks []string
	for _, r := range "prefix s3cret-token-value suffix" {
		chunks = append(chunks, string(r))
	}
	got := run(t, f, chunks...)
	want := "prefix «redacted:csrv/TOKEN» suffix"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Close is what emits the held-back tail. Without it the child's last line —
// often the one carrying the error — is silently truncated.
func TestCloseFlushesAPartialTail(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	var sink bytes.Buffer
	w := f.Writer(&sink)
	// A prefix of the value, and nothing more will arrive.
	if _, err := w.Write([]byte("tail s3cret-tok")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := sink.String(); got != "tail s3cret-tok" {
		t.Fatalf("a partial match at EOF was not flushed verbatim: %q", got)
	}
}

// A derived secret's value contains its inputs' values — that is what derive
// produces, and the drydock DSN is the live instance (SGNT-33). Matching
// shortest-first would replace the inner password and leave the surrounding
// value in clear: redacting the part already covered, disclosing the part that
// was not.
//
// The fixtures deliberately do not spell a connection string. A literal
// URI-with-password in a test file is the shape credential scanners exist to
// catch, and teaching the repo to ignore that shape is worse than the test
// being one character less realistic — containment is the only property under
// test, and the wrapper's form is irrelevant to it.
func TestLongestValueWins(t *testing.T) {
	const inner = "inner-secret-value"
	const outer = "wrapper[" + inner + "]wrapper"
	f := filterOf(
		Value{Name: "drydock/DB_PASSWORD", Plain: inner},
		Value{Name: "drydock/DSN", Plain: outer},
	)
	got := run(t, f, "dsn="+outer+"\n")
	if !strings.Contains(got, "«redacted:drydock/DSN»") {
		t.Fatalf("the containing value was not matched as itself: %q", got)
	}
	if strings.Contains(got, "wrapper") {
		t.Fatalf("part of the containing value survived in clear: %q", got)
	}
	if strings.Contains(got, inner) {
		t.Fatalf("the inner value survived in clear: %q", got)
	}
}

// A value below the floor would redact every occurrence of ordinary text —
// ports, line numbers, flags — and an operator who learns to read past
// «redacted:…» is one who will read past the placeholder that mattered.
// Excluding them is defensible; excluding them quietly is not.
func TestShortValuesAreSkippedAndReported(t *testing.T) {
	f := filterOf(
		Value{Name: "csrv/PORT", Plain: "5432"},
		Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"},
	)
	got := run(t, f, "listening on 5432 with s3cret-token-value\n")
	if !strings.Contains(got, "5432") {
		t.Fatalf("a short value was redacted, mangling ordinary output: %q", got)
	}
	if strings.Contains(got, "s3cret-token-value") {
		t.Fatalf("the real secret survived: %q", got)
	}
	if len(f.Skipped()) != 1 || f.Skipped()[0] != "csrv/PORT" {
		t.Fatalf("skipped = %v, want [csrv/PORT]", f.Skipped())
	}
	// The operator has to be able to size the guarantee, not just be told one
	// exists.
	if s := f.Summary(); !strings.Contains(s, "csrv/PORT") || !strings.Contains(s, "NOT redacted") {
		t.Fatalf("summary hides the gap in coverage: %q", s)
	}
}

// Replacement text must never be rescanned. A value that contains the
// placeholder's own text would otherwise be matched inside a replacement
// signet had just written, corrupting the output in a way that is very hard to
// read back.
func TestPlaceholdersAreNotRescanned(t *testing.T) {
	f := filterOf(Value{Name: "A", Plain: "redacted:A»x"})
	got := run(t, f, "value=redacted:A»x\n")
	if got != "value=«redacted:A»\n" {
		t.Fatalf("got %q", got)
	}
}

// Two secrets holding the same value is the hazard `derive` exists to retire,
// and it is still present in any vault that has not converted. The filter must
// not depend on map order to decide which name the operator sees.
func TestDuplicateValuesResolveDeterministically(t *testing.T) {
	first := run(t, filterOf(
		Value{Name: "b/SAME", Plain: "duplicated-value"},
		Value{Name: "a/SAME", Plain: "duplicated-value"},
	), "x duplicated-value y")
	for i := 0; i < 20; i++ {
		got := run(t, filterOf(
			Value{Name: "a/SAME", Plain: "duplicated-value"},
			Value{Name: "b/SAME", Plain: "duplicated-value"},
		), "x duplicated-value y")
		if got != first {
			t.Fatalf("placeholder varies between runs: %q then %q", first, got)
		}
	}
	if !strings.Contains(first, "a/SAME") {
		t.Fatalf("dedupe did not settle on the first name in order: %q", first)
	}
}

// Longest-wins has to hold across writes, not merely within whatever happens
// to be buffered. Where one managed value is a strict prefix of another — which
// `derive` produces whenever a template opens with its reference — a write
// ending exactly at the shorter value's last byte used to take the short match
// and forward the longer value's remaining bytes as plaintext.
//
// The result was worse than not redacting: a «redacted:…» telling the reader
// the filter ran, immediately followed by the tail of a credential it missed.
func TestAShortValueThatPrefixesALongerOneDoesNotLeakItsTail(t *testing.T) {
	short := "tok-abcdefgh"
	long := short + "IJKLMNOP"
	f := filterOf(
		Value{Name: "p/SHORT", Plain: short},
		Value{Name: "p/LONG", Plain: long},
	)

	// The split lands exactly on the shorter value's final byte.
	got := run(t, f, "start "+short, "IJKLMNOP end")
	if strings.Contains(got, "IJKLMNOP") {
		t.Fatalf("the longer value's tail was forwarded in clear: %q", got)
	}
	if got != "start «redacted:p/LONG» end" {
		t.Fatalf("got %q", got)
	}

	// And the same input in one write must agree, or the filter's answer
	// depends on how the kernel happened to chunk the stream.
	if one := run(t, f, "start "+long+" end"); one != got {
		t.Fatalf("split and whole disagree: %q vs %q", got, one)
	}

	// The shorter value must still be matched on its own, or the fix would
	// have been "hold everything forever".
	if alone := run(t, f, "start "+short+" end"); alone != "start «redacted:p/SHORT» end" {
		t.Fatalf("the shorter value stopped matching on its own: %q", alone)
	}
}

// Output that cannot match anything must not be held back. The loose
// implementation — always reserve maxLen bytes — stalls a child's interactive
// output behind a buffer waiting on a match that will never come.
func TestUnmatchableOutputIsNotHeldBack(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "zzzzzzzzzzzzzzzz"})
	var sink bytes.Buffer
	w := f.Writer(&sink)
	if _, err := w.Write([]byte("waiting for input: ")); err != nil {
		t.Fatal(err)
	}
	if got := sink.String(); got != "waiting for input: " {
		t.Fatalf("output with no possible match was buffered: %q", got)
	}
}

// An empty filter is a real configuration — a project whose values are all
// below the floor, or a vault with nothing resolvable — and it must behave as
// a plain pass-through rather than as an error or a stall.
func TestEmptyFilterPassesEverythingThrough(t *testing.T) {
	f := filterOf()
	got := run(t, f, "nothing ", "to redact\n")
	if got != "nothing to redact\n" {
		t.Fatalf("got %q", got)
	}
	if f.Len() != 0 {
		t.Fatalf("Len = %d", f.Len())
	}
}

func TestWriteReportsTheCallersByteCount(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	w := f.Writer(&bytes.Buffer{})
	// Held back entirely: a Write that reported the forwarded count here would
	// look like a short write to io.Copy and every wrapper built on it.
	p := []byte("s3cret-tok")
	n, err := w.Write(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(p) {
		t.Fatalf("n = %d, want %d", n, len(p))
	}
}

// Multi-line output with several occurrences, since the real case is a stack
// trace or an env dump rather than one tidy line.
func TestReplacesEveryOccurrence(t *testing.T) {
	f := filterOf(Value{Name: "csrv/TOKEN", Plain: "s3cret-token-value"})
	got := run(t, f, "a=s3cret-token-value\nb=s3cret-token-value\n")
	if strings.Contains(got, "s3cret-token-value") {
		t.Fatalf("an occurrence survived: %q", got)
	}
	if n := strings.Count(got, "«redacted:csrv/TOKEN»"); n != 2 {
		t.Fatalf("replaced %d occurrences, want 2", n)
	}
}
