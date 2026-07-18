// Package envfile parses and renders dotenv-style files.
//
// Parsing accepts the common dialect used across ~/projects: blank lines,
// full-line # comments, an optional "export " prefix, and values optionally
// wrapped in single or double quotes. Unquoted values are preserved verbatim —
// no inline-comment stripping, since real values (URLs, passwords) contain #.
//
// Rendering is canonical: managed header, keys sorted, values quoted only when
// needed. Render/Parse round-trip losslessly.
package envfile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Pair is one KEY=VALUE entry.
type Pair struct {
	Key   string
	Value string
}

// Header is the first line of every signet-rendered env file.
const Header = "# managed by signet — do not edit by hand"

// ParseFile parses the env file at path.
func ParseFile(path string) ([]Pair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pairs, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pairs, nil
}

// Parse reads dotenv pairs from r. Duplicate keys: last one wins.
func Parse(r io.Reader) ([]Pair, error) {
	var pairs []Pair
	index := map[string]int{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.Index(line, "=")
		if eq <= 0 {
			return nil, fmt.Errorf("line %d: not KEY=VALUE: %q", lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		value, err := unquote(strings.TrimSpace(line[eq+1:]))
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNo, key, err)
		}
		if i, dup := index[key]; dup {
			pairs[i].Value = value
			continue
		}
		index[key] = len(pairs)
		pairs = append(pairs, Pair{Key: key, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pairs, nil
}

// Map converts pairs to a lookup map.
func Map(pairs []Pair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.Key] = p.Value
	}
	return m
}

// Render produces the canonical managed-file content: header, sorted keys.
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
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\t", "\\t")
	return "\"" + r.Replace(v) + "\""
}
