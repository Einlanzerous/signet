// Package derive expands a secret whose value is composed from other secrets.
//
// The problem it exists for: a DSN like
// postgres://drydock_user:hunter2@127.0.0.1:5432/drydock stored as its own
// vault entry duplicates the password held in another entry. Rotate the
// password and the DSN is silently wrong — and `render --check` reports both
// files in sync, because each individually matches what the vault holds. The
// one tool whose job is noticing divergence structurally cannot notice this.
//
// A derived secret has no stored value. It holds a template naming the secrets
// it is built from, and is expanded at read time, so the composed value cannot
// drift from its inputs: there is nowhere for a stale copy to live.
package derive

import (
	"fmt"
	"strings"
)

// Ref is one {{...}} reference. An empty Project means "the project of the
// secret doing the deriving", which is resolved before lookup.
type Ref struct {
	Project string
	Name    string
}

func (r Ref) String() string {
	if r.Project == "" {
		return r.Name
	}
	return r.Project + "/" + r.Name
}

// QualifiedIn returns r with a bare reference's project filled in from the
// project doing the deriving. Exported because anything displaying a
// derivation's inputs — the CLI, a rotation's impact report — has to show the
// reference as it will actually resolve, not as it was typed.
func (r Ref) QualifiedIn(project string) Ref {
	if r.Project == "" {
		r.Project = project
	}
	return r
}

// qualify returns r with its project filled in from the deriving secret.
func (r Ref) qualify(origin Ref) Ref { return r.QualifiedIn(origin.Project) }

// Entry is what a lookup found: a derived secret reports its template, a plain
// one its value. A derived secret has no Value — that is the invariant the
// whole package rests on, not an omission.
type Entry struct {
	Derivation string
	Value      string
	Missing    bool
}

// Lookup resolves a fully-qualified reference.
type Lookup func(Ref) (Entry, error)

// maxDepth bounds recursion for a chain that is legal but absurd. Cycles are
// caught exactly by the path stack, so this only catches depth — it is a
// backstop against a pathological vault, not the cycle guard.
const maxDepth = 32

// segment is either literal text or a reference.
type segment struct {
	literal string
	ref     Ref
	isRef   bool
}

// Template is a parsed derivation.
type Template struct {
	segments []segment
	raw      string
}

// Raw returns the template as written.
func (t Template) Raw() string { return t.raw }

// Refs returns every reference in the template, in order, with duplicates
// retained — callers wanting a set can build one.
func (t Template) Refs() []Ref {
	var out []Ref
	for _, s := range t.segments {
		if s.isRef {
			out = append(out, s.ref)
		}
	}
	return out
}

// Parse reads a derivation template.
//
// It rejects a template with no references. Such a template is a literal value
// wearing a derivation's clothes: it would render a constant, be exempt from
// `set` because it is "derived", and never change when anything it supposedly
// depends on does. Storing a plain secret is the operation that already exists
// for that.
func Parse(tmpl string) (Template, error) {
	t := Template{raw: tmpl}
	rest := tmpl
	for {
		i := strings.Index(rest, "{{")
		if i < 0 {
			if rest != "" {
				t.segments = append(t.segments, segment{literal: rest})
			}
			break
		}
		if i > 0 {
			t.segments = append(t.segments, segment{literal: rest[:i]})
		}
		rest = rest[i+2:]
		j := strings.Index(rest, "}}")
		if j < 0 {
			return Template{}, fmt.Errorf("derivation %q: unterminated {{ — every reference needs a closing }}", tmpl)
		}
		ref, err := parseRef(rest[:j], tmpl)
		if err != nil {
			return Template{}, err
		}
		t.segments = append(t.segments, segment{ref: ref, isRef: true})
		rest = rest[j+2:]
	}
	if len(t.Refs()) == 0 {
		return Template{}, fmt.Errorf(
			"derivation %q names no secrets — a derivation with no {{reference}} is a constant, "+
				"which is what an ordinary secret already is; use `signet set` instead", tmpl)
	}
	return t, nil
}

func parseRef(body, tmpl string) (Ref, error) {
	s := strings.TrimSpace(body)
	if s == "" {
		return Ref{}, fmt.Errorf("derivation %q: empty {{}} reference", tmpl)
	}
	if strings.ContainsAny(s, " \t\n") {
		return Ref{}, fmt.Errorf("derivation %q: reference %q contains whitespace", tmpl, s)
	}
	switch strings.Count(s, "/") {
	case 0:
		return Ref{Name: s}, nil
	case 1:
		project, name, _ := strings.Cut(s, "/")
		if project == "" || name == "" {
			return Ref{}, fmt.Errorf("derivation %q: reference %q must be project/NAME or NAME", tmpl, s)
		}
		return Ref{Project: project, Name: name}, nil
	default:
		return Ref{}, fmt.Errorf("derivation %q: reference %q has more than one / — write project/NAME", tmpl, s)
	}
}

// Resolve expands a derivation into its final value.
//
// origin names the secret being derived; bare references resolve against its
// project, and it seeds the cycle path so a self-reference is reported as one.
func Resolve(origin Ref, tmpl string, look Lookup) (string, error) {
	t, err := Parse(tmpl)
	if err != nil {
		return "", err
	}
	return expand(origin, t, look, []Ref{origin}, map[Ref]string{})
}

// expand walks the template, resolving each reference.
//
// done memoizes references already expanded during this resolution. Without it
// a reference appearing twice is fetched and re-expanded twice, and a
// diamond-shaped graph — two derivations over one shared input, joined by a
// third — costs a number of store round-trips exponential in its depth. The
// cache is per-resolution rather than long-lived so a value can never be stale
// with respect to the vault it was read from.
//
// It is keyed by the qualified ref, which is also why it cannot mask a cycle:
// the path check runs before the cache is consulted, and the cache is only
// populated by references that already returned.
func expand(origin Ref, t Template, look Lookup, path []Ref, done map[Ref]string) (string, error) {
	if len(path) > maxDepth {
		return "", fmt.Errorf("derivation nested more than %d deep at %s — %s", maxDepth, origin, chain(path))
	}
	var b strings.Builder
	for _, seg := range t.segments {
		if !seg.isRef {
			b.WriteString(seg.literal)
			continue
		}
		ref := seg.ref.qualify(origin)
		// Checked before both the cache and the lookup, so a cycle is named as
		// a cycle rather than as whatever the recursion happens to fail on
		// first — and so a repeat reference on a legal diamond is still
		// distinguished from one closing a loop.
		for _, seen := range path {
			if seen == ref {
				return "", fmt.Errorf("derivation cycle: %s", chain(append(path, ref)))
			}
		}
		if v, ok := done[ref]; ok {
			b.WriteString(v)
			continue
		}
		e, err := look(ref)
		if err != nil {
			return "", err
		}
		if e.Missing {
			// Names the deriving secret as well as the missing one: the operator
			// is looking at a render that failed, and "no such secret" without
			// saying who wanted it sends them hunting.
			return "", fmt.Errorf("%s derives from %s, which the vault does not have", origin, ref)
		}
		if e.Derivation == "" {
			done[ref] = e.Value
			b.WriteString(e.Value)
			continue
		}
		inner, err := Parse(e.Derivation)
		if err != nil {
			return "", fmt.Errorf("%s: %w", ref, err)
		}
		v, err := expand(ref, inner, look, append(path, ref), done)
		if err != nil {
			return "", err
		}
		done[ref] = v
		b.WriteString(v)
	}
	return b.String(), nil
}

// chain renders a reference path as a → b → c, which is the form that makes a
// cycle obvious at a glance.
func chain(path []Ref) string {
	parts := make([]string, len(path))
	for i, r := range path {
		parts[i] = r.String()
	}
	return strings.Join(parts, " → ")
}
