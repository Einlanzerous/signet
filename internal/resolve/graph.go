package resolve

import (
	"fmt"

	"github.com/Einlanzerous/signet/internal/derive"
	"github.com/Einlanzerous/signet/internal/store"
)

// refOf names a secret.
func refOf(sec store.Secret) derive.Ref {
	return derive.Ref{Project: sec.Project, Name: sec.Name}
}

// inputsOf returns the references a derived secret reads directly, qualified
// against its own project so a bare {{NAME}} resolves the way it will at render
// time. A text match on the template cannot do this, which is why every caller
// goes through here.
func inputsOf(sec store.Secret) ([]derive.Ref, error) {
	t, err := derive.Parse(sec.Derivation)
	if err != nil {
		return nil, fmt.Errorf("%s/%s has an invalid derivation: %w", sec.Project, sec.Name, err)
	}
	var out []derive.Ref
	for _, r := range t.Refs() {
		out = append(out, r.QualifiedIn(sec.Project))
	}
	return out, nil
}

// Dependents returns every derived secret whose value changes when
// (project, name) changes — following chains, not just direct references.
//
// Transitive because derivations chain: a secret built from a secret built from
// the one being rotated changes just as surely, and a report naming only the
// first level under-reports what a rotation did. Under-reporting here is the
// failure this whole feature exists to prevent, so stopping at depth one would
// have reproduced it in the tool meant to reveal it.
//
// It lives here rather than in store because deciding what a template refers to
// is derivation semantics, not persistence — store would have to import derive
// and filter rows in Go to answer it, which is what this package is for.
func Dependents(st *store.Store, project, name string) ([]store.Secret, error) {
	all, err := st.ListSecrets()
	if err != nil {
		return nil, err
	}
	// Reverse edges: input ref -> the derived secrets reading it.
	readers := map[derive.Ref][]store.Secret{}
	for _, sec := range all {
		if !sec.Derived() {
			continue
		}
		refs, err := inputsOf(sec)
		if err != nil {
			// A template that no longer parses means this secret cannot render
			// at all — better learned during a rotation than during the deploy
			// after it.
			return nil, err
		}
		for _, r := range refs {
			readers[r] = append(readers[r], sec)
		}
	}

	var out []store.Secret
	seen := map[derive.Ref]bool{}
	queue := []derive.Ref{{Project: project, Name: name}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, sec := range readers[cur] {
			r := refOf(sec)
			// Guards both re-reporting a diamond's shared node and looping on a
			// cycle. A cycle cannot render, but Dependents is called from
			// rotation paths that must not hang on a vault that has one.
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, sec)
			queue = append(queue, r)
		}
	}
	return out, nil
}

// Inputs returns every secret that contributes a value to sec, transitively,
// excluding sec itself.
//
// It exists so a reveal can record disclosure against the ledgers of the
// secrets actually disclosed. Revealing a derived secret prints its inputs'
// plaintext — across projects — and an entry written only against the derived
// secret leaves those inputs' own ledgers silent about it, which is an
// unaudited read channel in a vault whose premise is that plaintext leaves only
// in audited ways.
func Inputs(st *store.Store, sec *store.Secret) ([]store.Secret, error) {
	if !sec.Derived() {
		return nil, nil
	}
	var out []store.Secret
	seen := map[derive.Ref]bool{refOf(*sec): true}
	queue, err := inputsOf(*sec)
	if err != nil {
		return nil, err
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		found, err := st.GetSecret(cur.Project, cur.Name)
		if err != nil {
			return nil, err
		}
		if found == nil {
			// Resolution reports missing inputs with a better message than this
			// could; here it is simply not a secret whose ledger can be written.
			continue
		}
		out = append(out, *found)
		if found.Derived() {
			next, err := inputsOf(*found)
			if err != nil {
				return nil, err
			}
			queue = append(queue, next...)
		}
	}
	return out, nil
}
