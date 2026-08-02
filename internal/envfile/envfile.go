// Package envfile parses and renders dotenv-style files.
//
// Parsing accepts the common dialect used across ~/projects: blank lines,
// full-line # comments, an optional "export " prefix, and values optionally
// wrapped in single or double quotes. Unquoted values are preserved verbatim —
// no inline-comment stripping, since real values (URLs, passwords) contain #.
//
// There are two ways to render, and the difference matters:
//
//   - Render is canonical — managed header, keys sorted, values quoted only when
//     needed. It describes a whole file, so it is only for files signet is
//     creating. Render/Parse round-trip losslessly.
//   - RenderInto merges into a file that already exists, replacing the values of
//     the keys it is given and touching nothing else. Comments, blank lines, key
//     order and keys signet does not manage survive it.
//
// Env files are hand-maintained and gitignored: whatever a canonical rewrite
// discards is gone for good, with no copy anywhere to restore from. That is why
// the merge path — not the canonical one — is what `signet render` writes with.
package envfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// Pair is one KEY=VALUE entry.
type Pair struct {
	Key   string
	Value string
}

// Header is the first line of every env file signet creates.
const Header = "# managed by signet — managed values are overwritten on render; other lines are kept"

// priorHeaders is every header signet has ever written, current one first. The
// line states a promise about what render does to the file, so when the promise
// changes the stale line is replaced rather than left standing — but only when it
// is one of these exactly, so a hand-written line is never mistaken for one.
// Changing Header means adding the old text here, not editing it.
var priorHeaders = []string{
	Header,
	"# managed by signet — do not edit by hand",
}

// Document is a parsed env file with its original shape intact: every comment,
// blank line and entry in source order, each entry remembering the exact text it
// was read from. Editing a value rewrites that entry and nothing else, so a file
// can be updated without being retyped.
type Document struct {
	nodes []node
}

// node is one logical line of a Document — a comment, a blank, or an entry.
// A multi-line value (quoted or PEM) is a single node spanning several physical
// lines.
type node struct {
	// raw is the verbatim source, newline-joined across continuation lines. It
	// is what gets written back for anything not edited, which is what keeps
	// unmanaged entries byte-identical rather than merely equivalent.
	raw string
	// head is an entry's source text through the "=" — indentation, an "export "
	// prefix, spacing around the separator. Rewriting a value re-emits head so
	// none of that is lost to the edit.
	head  string
	key   string // "" when this node is not an entry
	value string
	// edited marks a value replaced since parsing: raw no longer describes this
	// node, so it is re-emitted from head + value.
	edited bool
}

// ParseFile parses the env file at path.
func ParseFile(path string) ([]Pair, error) {
	doc, err := ParseDocumentFile(path)
	if err != nil {
		return nil, err
	}
	return doc.Pairs(), nil
}

// ParseDocumentFile parses the env file at path, keeping its structure.
func ParseDocumentFile(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	doc, err := ParseDocument(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// Parse reads dotenv pairs from r. Duplicate keys: last one wins.
func Parse(r io.Reader) ([]Pair, error) {
	doc, err := ParseDocument(r)
	if err != nil {
		return nil, err
	}
	return doc.Pairs(), nil
}

// ParseDocument reads r into a Document, preserving comments, blank lines and
// entry order along with the pairs themselves.
func ParseDocument(r io.Reader) (*Document, error) {
	doc := &Document{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		src := scanner.Text()
		line := strings.TrimSpace(src)
		if line == "" || strings.HasPrefix(line, "#") {
			doc.nodes = append(doc.nodes, node{raw: src})
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.Index(line, "=")
		if eq <= 0 {
			return nil, fmt.Errorf("line %d: not KEY=VALUE: %q", lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		raw := strings.TrimSpace(line[eq+1:])
		// head is measured on the untrimmed source: the separator is the first
		// "=" either way, since only indentation, "export " and the key precede
		// it, and none of those can contain one.
		n := node{raw: src, head: src[:strings.Index(src, "=")+1], key: key}
		// A quoted value whose closing quote isn't on this line (e.g. a
		// multi-line PEM private key) continues onto following lines until the
		// matching quote is found. Physical lines are rejoined with "\n".
		if q := openingQuote(raw); q != 0 && !quoteClosed(raw, q) {
			var sb, rawSrc strings.Builder
			sb.WriteString(raw)
			rawSrc.WriteString(src)
			closed := false
			for scanner.Scan() {
				lineNo++
				rawSrc.WriteByte('\n')
				rawSrc.WriteString(scanner.Text())
				sb.WriteByte('\n')
				sb.WriteString(strings.TrimSpace(scanner.Text()))
				if quoteClosed(sb.String(), q) {
					closed = true
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("line %d (%s): unterminated quoted value", lineNo, key)
			}
			raw, n.raw = sb.String(), rawSrc.String()
		} else if pemOpen(raw) {
			// Unquoted PEM block (e.g. an RSA/service-account key written as raw
			// wrapped lines). Self-delimiting: accumulate until the -----END----- line.
			var sb, rawSrc strings.Builder
			sb.WriteString(raw)
			rawSrc.WriteString(src)
			closed := false
			for scanner.Scan() {
				lineNo++
				l := strings.TrimSpace(scanner.Text())
				rawSrc.WriteByte('\n')
				rawSrc.WriteString(scanner.Text())
				sb.WriteByte('\n')
				sb.WriteString(l)
				if strings.HasPrefix(l, "-----END") {
					closed = true
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("line %d (%s): unterminated PEM block", lineNo, key)
			}
			raw, n.raw = sb.String(), rawSrc.String()
		}
		value, err := unquote(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNo, key, err)
		}
		n.value = value
		doc.nodes = append(doc.nodes, n)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return doc, nil
}

// Pairs returns the document's entries, one per key. Duplicate keys collapse to
// the last value at the first key's position, which is what a dotenv reader
// resolves them to.
func (d *Document) Pairs() []Pair {
	var pairs []Pair
	index := map[string]int{}
	for _, n := range d.nodes {
		if n.key == "" {
			continue
		}
		if i, dup := index[n.key]; dup {
			pairs[i].Value = n.value
			continue
		}
		index[n.key] = len(pairs)
		pairs = append(pairs, Pair{Key: n.key, Value: n.value})
	}
	return pairs
}

// Keys returns the entry keys in source order, deduplicated.
func (d *Document) Keys() []string {
	pairs := d.Pairs()
	keys := make([]string, len(pairs))
	for i, p := range pairs {
		keys[i] = p.Key
	}
	return keys
}

// Set gives key the value, in place, or appends an entry when the document has
// none. A key written more than once has every occurrence updated: leaving the
// earlier ones stale would make the file's history read as if the value had
// changed between them.
func (d *Document) Set(key, value string) {
	found := false
	for i := range d.nodes {
		if d.nodes[i].key != key {
			continue
		}
		found = true
		if d.nodes[i].value == value {
			continue
		}
		d.nodes[i].value = value
		d.nodes[i].edited = true
	}
	if !found {
		d.insertEntry(node{head: key + "=", key: key, value: value, edited: true})
	}
}

// insertEntry places a new entry directly after the last one in the document
// rather than at the end of the file. Appending past the end files the key under
// whatever trailing comment happens to be last, which reads as a claim about the
// key that signet has no basis for. Landing among the other entries says nothing
// it cannot support.
func (d *Document) insertEntry(n node) {
	last := -1
	for i := range d.nodes {
		if d.nodes[i].key != "" {
			last = i
		}
	}
	if last == len(d.nodes)-1 { // includes the no-entries case (-1 == len-1 only when empty)
		d.nodes = append(d.nodes, n)
		return
	}
	if last < 0 {
		d.nodes = append(d.nodes, n) // comments only: nothing to sit beside
		return
	}
	d.nodes = append(d.nodes, node{})
	copy(d.nodes[last+2:], d.nodes[last+1:])
	d.nodes[last+1] = n
}

// Remove deletes every entry for key, reporting whether it removed anything.
// Comments around it stay: signet cannot tell which of them described the entry.
func (d *Document) Remove(key string) bool {
	kept := d.nodes[:0]
	removed := false
	for _, n := range d.nodes {
		if n.key == key {
			removed = true
			continue
		}
		kept = append(kept, n)
	}
	d.nodes = kept
	return removed
}

// String renders the document back to file content. Untouched nodes are written
// from their original text, so anything signet did not edit comes back as it was
// read, with two normalizations that come from reading the file by line: lines
// are terminated with "\n" (a CRLF file is rewritten LF), and the last line
// always gets a terminator whether or not it had one. Every env file on this
// host is already LF-terminated, so in practice a file that is not edited is
// reproduced byte for byte.
func (d *Document) String() string {
	var b strings.Builder
	for _, n := range d.nodes {
		if n.edited {
			b.WriteString(n.head)
			b.WriteString(maybeQuote(n.value))
		} else {
			b.WriteString(n.raw)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// refreshHeader replaces a signet header carrying older wording, so a file does
// not go on making a promise about render that render no longer keeps. A file
// without one does not get one: render adds no lines to a file it did not write.
//
// The match is against the exact text of a header signet has written, never a
// prefix. A hand-written line that merely opens with the same words is someone's
// own sentence, and overwriting it is the precise thing this whole change exists
// to stop — a loose match here would make the one function whose job is not
// destroying hand-written lines the one that destroys them.
func (d *Document) refreshHeader() {
	for i := range d.nodes {
		if d.nodes[i].key != "" {
			return // an entry came first; there is no header to refresh
		}
		line := strings.TrimSpace(d.nodes[i].raw)
		if line == "" {
			continue // leading blank lines
		}
		for _, known := range priorHeaders {
			if line == known {
				d.nodes[i].raw = Header
				break
			}
		}
		return // only the first non-blank line can be the header
	}
}

// isEmpty reports whether the document holds nothing worth preserving — no
// entries and no comments. A file like that is shape signet would be pretending
// to find, so it is rendered as if it were not there at all.
func (d *Document) isEmpty() bool {
	for _, n := range d.nodes {
		if n.key != "" || strings.TrimSpace(n.raw) != "" {
			return false
		}
	}
	return true
}

// Map converts pairs to a lookup map.
func Map(pairs []Pair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.Key] = p.Value
	}
	return m
}

// RenderInto returns the content to write for a file target: pairs merged into
// whatever is already at path. It also returns the keys the file holds that
// pairs does not name — carried through into the content, or dropped from it and
// listed for the caller to report when prune is set.
//
// A file that is missing, or present but holding nothing to preserve, is
// rendered canonically; there is no shape to keep, and this is the
// disaster-recovery case render exists for. A file that is present but
// unparseable is an error rather than a rewrite: the content cannot be read, so
// it cannot be merged into, and overwriting it would destroy the very thing the
// parse failure says signet does not understand.
//
// The not-exist test unwraps. It is the single branch standing between a live
// file and a canonical rewrite of it, so it does not rest on an error happening
// to arrive unwrapped from wherever it was raised.
func RenderInto(path string, pairs []Pair, prune bool) (content string, unmanaged []string, err error) {
	doc, err := ParseDocumentFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Render(pairs), nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if doc.isEmpty() {
		return Render(pairs), nil, nil
	}
	managed := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		managed[p.Key] = true
		doc.Set(p.Key, p.Value)
	}
	for _, k := range doc.Keys() {
		if managed[k] {
			continue
		}
		unmanaged = append(unmanaged, k)
		if prune {
			doc.Remove(k)
		}
	}
	doc.refreshHeader()
	return doc.String(), unmanaged, nil
}

// Render produces the canonical managed-file content: header, sorted keys.
//
// It describes an entire file, so it is for files signet is creating. Rendering
// over a file that already exists goes through RenderInto — this drops
// everything not in pairs.
func Render(pairs []Pair) string {
	sorted := append([]Pair(nil), pairs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	var b strings.Builder
	b.WriteString(Header + "\n")
	for _, p := range sorted {
		b.WriteString(p.Key)
		b.WriteByte('=')
		b.WriteString(maybeQuote(p.Value))
		b.WriteByte('\n')
	}
	return b.String()
}

// openingQuote returns the leading quote byte if v starts with one, else 0.
func openingQuote(v string) byte {
	if len(v) > 0 && (v[0] == '"' || v[0] == '\'') {
		return v[0]
	}
	return 0
}

// quoteClosed reports whether v is a complete q-quoted token: it opens with q
// and ends with an unescaped q. Single quotes are literal (no escapes); for
// double quotes the trailing quote must be preceded by an even number of
// backslashes. Base64/PEM bodies never contain a bare quote, so accumulation
// across lines terminates exactly at the real closing quote.
func quoteClosed(v string, q byte) bool {
	if len(v) < 2 || v[0] != q || v[len(v)-1] != q {
		return false
	}
	if q == '\'' {
		return true
	}
	bs := 0
	for i := len(v) - 2; i >= 1 && v[i] == '\\'; i-- {
		bs++
	}
	return bs%2 == 0
}

// pemOpen reports whether an unquoted value begins a multi-line PEM block whose
// terminator is on a later line. The "-----BEGIN"/"-----END" markers make the
// block self-delimiting, so accumulation is unambiguous without surrounding quotes.
func pemOpen(v string) bool {
	return strings.HasPrefix(v, "-----BEGIN") && !strings.Contains(v, "-----END")
}

// unquote strips a matching pair of surrounding quotes. Double-quoted values
// support \" \\ \n \t escapes; single-quoted values are literal.
func unquote(v string) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		inner := v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c != '\\' {
				b.WriteByte(c)
				continue
			}
			i++
			if i >= len(inner) {
				return "", fmt.Errorf("dangling escape at end of value")
			}
			switch inner[i] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				// Preserve unknown escapes verbatim.
				b.WriteByte('\\')
				b.WriteByte(inner[i])
			}
		}
		return b.String(), nil
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1], nil
	}
	return v, nil
}

func needsQuote(v string) bool {
	if v == "" {
		return true
	}
	if strings.TrimSpace(v) != v {
		return true
	}
	return strings.ContainsAny(v, " \t\n#\"'\\")
}

func maybeQuote(v string) string {
	if !needsQuote(v) {
		return v
	}
	// A value that arrived as a block of real lines — a PEM key is the case that
	// matters — is written back as one. Collapsing it to a backslash-escaped
	// single line is a format change on exactly the values whose format is load
	// bearing: signet's own parser reads "\n" back, but `source .env` and
	// compose's env_file hand the consumer a literal backslash and an n, so a
	// rotation would break a key that was working before it.
	if blockSafe(v) {
		return "\"" + v + "\""
	}
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\t", "\\t")
	return "\"" + r.Replace(v) + "\""
}

// blockSafe reports whether v can be written as a literal multi-line block that
// Parse reads back byte for byte.
//
// It needs no escaping (no quote to close the block early, no backslash to be
// read as one), and no line may carry leading or trailing whitespace, since
// accumulation trims each continuation line and would not give it back. PEM
// bodies satisfy all of this; anything that does not falls back to the escaped
// single line, which is uglier but never lossy.
func blockSafe(v string) bool {
	if !strings.Contains(v, "\n") || strings.ContainsAny(v, "\"\\") {
		return false
	}
	for _, line := range strings.Split(v, "\n") {
		if strings.TrimSpace(line) != line {
			return false
		}
	}
	return true
}
