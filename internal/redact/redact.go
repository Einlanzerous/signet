// Package redact filters a byte stream, replacing known secret values with a
// named placeholder as they pass through.
//
// It exists because signet is the one tool in the estate that knows the whole
// set of values it manages. A generic secret manager cannot do this: it can
// avoid printing a value itself, but it cannot notice one going past in a
// child process's output. That difference is what turns "the caller did not
// echo it" into "the stream was filtered on the way out" — an accidental
// `echo $TOKEN`, a curl dumping request headers on error, a stack trace
// carrying the environment.
//
// # What this does not do
//
// It bounds accidents, not intent. A child process that wants to disclose a
// value can encode it — base64, line-wrapping, character-by-character — and
// nothing here will match. Reading this as a boundary against a hostile
// process would be the same false guarantee as a permission rule that gates
// the honest path and leaves the indirect one open.
//
// Accidental leakage is the actual failure mode with an otherwise-trusted
// child, and it is the one this makes structurally hard.
package redact

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// MinLength is the shortest value the filter will match on.
//
// A floor is not a nicety. A secret whose value is "1", "true" or "5432" would
// redact every occurrence of that text in the child's output — line numbers,
// timestamps, unrelated ports — producing a stream that is unreadable and, far
// worse, one where the placeholders no longer mean anything. An operator who
// learns to read past «redacted:…» is an operator who will read past the one
// that mattered.
//
// Eight matches the shortest value signet's own consumers will accept, and it
// excludes the class of entry that is not a credential at all (image tags,
// ports, feature flags — see SGNT-30). Values below it are reported by
// Skipped rather than silently dropped: understating coverage quietly is how a
// filter comes to be trusted for something it never did.
const MinLength = 8

// Value is one secret the filter knows about.
type Value struct {
	Name  string // "project/NAME", used in the placeholder
	Plain string
}

// Filter replaces known values in a stream. The zero Filter is not usable;
// build one with New.
type Filter struct {
	// byFirst indexes candidates by their first byte, so a position in the
	// stream is compared only against values that could start there. Without
	// it every byte of output is compared against every known value, which for
	// a vault-wide filter over a chatty command is the difference between
	// negligible and noticeable.
	byFirst map[byte][]candidate
	maxLen  int
	skipped []string
}

type candidate struct {
	plain       []byte
	placeholder []byte
}

// New builds a filter over the values worth matching, and reports the names it
// excluded for being shorter than MinLength.
//
// Values are matched longest-first, so a value that contains another — a DSN
// holding a password, which is exactly what `derive` produces — is replaced as
// itself rather than left as a shell around an inner placeholder.
func New(values []Value) *Filter {
	f := &Filter{byFirst: map[byte][]candidate{}}
	// Sorted before dedupe so that two secrets sharing a value (the hazard
	// `derive` exists to retire, and still present in vaults that have not
	// converted) resolve to the same placeholder every run rather than to
	// whichever the map yielded first.
	sorted := append([]Value(nil), values...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i].Plain) != len(sorted[j].Plain) {
			return len(sorted[i].Plain) > len(sorted[j].Plain)
		}
		if sorted[i].Plain != sorted[j].Plain {
			return sorted[i].Plain < sorted[j].Plain
		}
		return sorted[i].Name < sorted[j].Name
	})
	seen := map[string]bool{}
	for _, v := range sorted {
		if v.Plain == "" || seen[v.Plain] {
			continue
		}
		if len(v.Plain) < MinLength {
			f.skipped = append(f.skipped, v.Name)
			continue
		}
		seen[v.Plain] = true
		c := candidate{
			plain:       []byte(v.Plain),
			placeholder: []byte(fmt.Sprintf("«redacted:%s»", v.Name)),
		}
		b := c.plain[0]
		f.byFirst[b] = append(f.byFirst[b], c)
		if len(c.plain) > f.maxLen {
			f.maxLen = len(c.plain)
		}
	}
	sort.Strings(f.skipped)
	return f
}

// Skipped names the values excluded for being shorter than MinLength, in order.
func (f *Filter) Skipped() []string { return f.skipped }

// Len reports how many distinct values the filter will match.
func (f *Filter) Len() int {
	n := 0
	for _, cs := range f.byFirst {
		n += len(cs)
	}
	return n
}

// Writer wraps w so that values known to f are replaced on the way through.
//
// Callers MUST Close it. A value split across two Write calls is the case this
// whole type exists for — a 40-character token arriving as 30 bytes and then
// 10 is not a special case, it is what a pipe does — so the tail of each write
// is held back until enough bytes arrive to rule out a match. Close flushes
// what is left; dropping it truncates the child's last line.
func (f *Filter) Writer(w io.Writer) *Writer {
	return &Writer{f: f, w: w}
}

// Writer is the stream filter returned by Filter.Writer.
type Writer struct {
	f   *Filter
	w   io.Writer
	mu  sync.Mutex
	buf []byte
}

// Write filters p and passes on everything that cannot still be part of a
// value. It reports len(p) consumed on success: the caller wrote those bytes,
// and the count is about their buffer, not about how many bytes the filter
// chose to forward.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	out, keep := w.f.scan(w.buf, false)
	w.buf = append(w.buf[:0], keep...)
	if len(out) > 0 {
		if _, err := w.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close flushes the held-back tail. At end of stream a partial match is not a
// match — there are no more bytes coming — so the remainder is scanned with no
// holdback and emitted.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return nil
	}
	out, _ := w.f.scan(w.buf, true)
	w.buf = w.buf[:0]
	_, err := w.w.Write(out)
	return err
}

// scan walks buf left to right, replacing complete matches. It returns the
// bytes safe to emit and the bytes to hold for the next write.
//
// The walk copies rather than rewriting in place, so a placeholder is never
// itself rescanned — a value that happened to contain the placeholder text
// could otherwise be matched inside a replacement signet had just written.
//
// With eof set nothing is held back.
func (f *Filter) scan(buf []byte, eof bool) (out, keep []byte) {
	out = make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		if c, ok := f.matchAt(buf, i); ok {
			out = append(out, c.placeholder...)
			i += len(c.plain)
			continue
		}
		// Not a complete match. If what remains could still become one once
		// more bytes arrive, stop here and keep the rest.
		if !eof && len(buf)-i < f.maxLen && f.couldStart(buf[i:]) {
			break
		}
		out = append(out, buf[i])
		i++
	}
	return out, buf[i:]
}

// matchAt reports the longest known value starting at buf[i]. Candidates are
// held longest-first per first byte, so the first hit is the longest.
func (f *Filter) matchAt(buf []byte, i int) (candidate, bool) {
	for _, c := range f.byFirst[buf[i]] {
		if bytes.HasPrefix(buf[i:], c.plain) {
			return c, true
		}
	}
	return candidate{}, false
}

// couldStart reports whether tail is a proper prefix of some known value, and
// therefore whether holding it back could still yield a match.
//
// Checked precisely rather than by always reserving maxLen bytes: the loose
// version holds back the tail of every write regardless of content, which
// stalls interactive output behind a buffer that will never match anything.
func (f *Filter) couldStart(tail []byte) bool {
	for _, c := range f.byFirst[tail[0]] {
		if len(tail) < len(c.plain) && bytes.HasPrefix(c.plain, tail) {
			return true
		}
	}
	return false
}

// Summary describes the filter's coverage for the operator, so that "output was
// filtered" is a claim they can size rather than take on faith.
func (f *Filter) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "redacting %d value(s) from the child's output", f.Len())
	if n := len(f.skipped); n > 0 {
		fmt.Fprintf(&b, "; %d shorter than %d chars are NOT redacted: %s",
			n, MinLength, strings.Join(f.skipped, ", "))
	}
	return b.String()
}
