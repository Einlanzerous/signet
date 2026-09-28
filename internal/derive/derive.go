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
//
// A reference may carry a transform — {{PASSWORD | scrypt}} — for the values
// that have to reach their destination encoded or hashed. A transform is
// computed at read time like everything else and must give the same output
// every time; see transform.go for why that is enforced at declaration.
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

// segment is either literal text or a reference, optionally transformed.
type segment struct {
	literal   string
	ref       Ref
	transform string
	isRef     bool
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
//
// A transformed reference is still a reference. The dependency graph, the
// rotation impact report and the disclosure audit all walk this list, and a
// transform changes what is written to the destination, not what it was built
// from — an input hashed with scrypt is no less an input.
func (t Template) Refs() []Ref {
	var out []Ref
	for _, u := range t.Uses() {
		out = append(out, u.Ref)
	}
	return out
}

// Use is one reference as the template applies it.
type Use struct {
	Ref Ref
	// Transform is the name applied to the reference's value, empty for none.
	Transform string
}

// Uses is Refs with what each reference is put through, for anything that
// displays a derivation and would otherwise show a hash as a plain copy.
func (t Template) Uses() []Use {
	var out []Use
	for _, s := range t.segments {
		if s.isRef {
			out = append(out, Use{Ref: s.ref, Transform: s.transform})
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
		ref, xform, err := parseRef(rest[:j], tmpl)
		if err != nil {
			return Template{}, err
		}
		t.segments = append(t.segments, segment{ref: ref, transform: xform, isRef: true})
		rest = rest[j+2:]
	}
	if len(t.Refs()) == 0 {
		return Template{}, fmt.Errorf(
			"derivation %q names no secrets — a derivation with no {{reference}} is a constant, "+
				"which is what an ordinary secret already is; use `signet set` instead", tmpl)
	}
	return t, nil
}

// parseRef reads the inside of one {{...}}: a reference, or a reference piped
// through a transform.
//
// The pipe has to be set off by whitespace, and that is what keeps it
// unambiguous. Names are not validated anywhere in this codebase, so a project
// or secret could legitimately contain `|` or `:` — a marker built from either
// would change what an existing template means. Whitespace inside a reference
// has been an error since derivations began, so `NAME | scrypt` is a form no
// stored template can already hold, and `a|b` remains a reference to a secret
// named a|b exactly as before.
//
// Exactly one transform per reference. Composing two is possible by deriving an
// intermediate secret, which keeps each step visible in `status` and `reveal`;
// a chain inside one pair of braces is a hash of a hash no one can read back.
func parseRef(body, tmpl string) (Ref, string, error) {
	s := strings.TrimSpace(body)
	if s == "" {
		return Ref{}, "", fmt.Errorf("derivation %q: empty {{}} reference", tmpl)
	}
	fields := strings.Fields(s)
	xform := ""
	switch {
	case len(fields) == 1:
	case fields[1] == "|" && len(fields) == 2:
		return Ref{}, "", fmt.Errorf("derivation %q: %q names no transform after the |", tmpl, s)
	case fields[1] == "|" && len(fields) == 3:
		xform = fields[2]
		if _, err := lookupTransform(xform, tmpl); err != nil {
			return Ref{}, "", err
		}
	case fields[1] == "|" && len(fields) > 3 && fields[3] == "|":
		return Ref{}, "", fmt.Errorf("derivation %q: %q applies more than one transform — "+
			"one per reference; derive an intermediate secret to chain them", tmpl, s)
	default:
		return Ref{}, "", fmt.Errorf("derivation %q: reference %q contains whitespace "+
			"(the only form with a space is {{NAME | transform}})", tmpl, s)
	}
	s = fields[0]
	switch strings.Count(s, "/") {
	case 0:
		return Ref{Name: s}, xform, nil
	case 1:
		project, name, _ := strings.Cut(s, "/")
		if project == "" || name == "" {
			return Ref{}, "", fmt.Errorf("derivation %q: reference %q must be project/NAME or NAME", tmpl, s)
		}
		return Ref{Project: project, Name: name}, xform, nil
	default:
		return Ref{}, "", fmt.Errorf("derivation %q: reference %q has more than one / — write project/NAME", tmpl, s)
	}
}

// Resolve expands a derivation into its final value.
//
// origin names the secret being derived; bare references resolve against its
// project, and it seeds the cycle path so a self-reference is reported as one.
//
// key is the vault's master key, which a salted transform needs and nothing
// else here does. It is a required argument rather than an option so a caller
// cannot resolve without deciding what to pass; passing none makes a transform
// that needs one fail, never salt with nothing.
func Resolve(origin Ref, tmpl string, look Lookup, key []byte) (string, error) {
	t, err := Parse(tmpl)
	if err != nil {
		return "", err
	}
	r := resolver{look: look, key: key, done: map[Ref]string{}}
	return r.expand(origin, t, []Ref{origin})
}

// resolver carries one resolution's state.
//
// done memoizes references already expanded during this resolution. Without it
// a reference appearing twice is fetched and re-expanded twice, and a
// diamond-shaped graph — two derivations over one shared input, joined by a
// third — costs a number of store round-trips exponential in its depth. The
// cache is per-resolution rather than long-lived so a value can never be stale
// with respect to the vault it was read from.
//
// It holds a reference's value *before* any transform: two templates applying
// different transforms to one input share the entry, and a transformed value
// is never mistaken for the input it came from.
//
// It is keyed by the qualified ref, which is also why it cannot mask a cycle:
// the path check runs before the cache is consulted, and the cache is only
// populated by references that already returned.
type resolver struct {
	look Lookup
	key  []byte
	done map[Ref]string
}

// expand walks the template, resolving each reference and applying its
// transform.
func (r *resolver) expand(origin Ref, t Template, path []Ref) (string, error) {
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
		v, err := r.value(origin, ref, path)
		if err != nil {
			return "", err
		}
		if seg.transform != "" {
			v, err = r.transform(origin, ref, seg.transform, t.raw, v)
			if err != nil {
				return "", err
			}
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

// value returns a reference's own value, before any transform.
func (r *resolver) value(origin, ref Ref, path []Ref) (string, error) {
	// Checked before both the cache and the lookup, so a cycle is named as
	// a cycle rather than as whatever the recursion happens to fail on
	// first — and so a repeat reference on a legal diamond is still
	// distinguished from one closing a loop.
	for _, seen := range path {
		if seen == ref {
			return "", fmt.Errorf("derivation cycle: %s", chain(append(path, ref)))
		}
	}
	if v, ok := r.done[ref]; ok {
		return v, nil
	}
	e, err := r.look(ref)
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
		r.done[ref] = e.Value
		return e.Value, nil
	}
	inner, err := Parse(e.Derivation)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ref, err)
	}
	v, err := r.expand(ref, inner, append(path, ref))
	if err != nil {
		return "", err
	}
	r.done[ref] = v
	return v, nil
}

// transform applies a named transform to input, the value of ref as read for
// the derivation of origin.
//
// The name was validated when the template was parsed, so the lookup here is
// the same gate a second time rather than a new failure mode — but it is the
// one path from a name to behaviour, which is worth more than skipping it. An
// error names the transform and both ends, and never the input: a failure here
// is printed by render, and the input is a credential.
func (r *resolver) transform(origin, ref Ref, name, tmpl, input string) (string, error) {
	tr, err := lookupTransform(name, tmpl)
	if err != nil {
		return "", err
	}
	out, err := tr.apply(transformCtx{origin: origin, key: r.key}, input)
	if err != nil {
		return "", fmt.Errorf("%s: applying %s to %s: %w", origin, name, ref, err)
	}
	return out, nil
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
