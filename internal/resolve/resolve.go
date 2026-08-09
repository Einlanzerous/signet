// Package resolve answers one question for the whole codebase: what is this
// secret's plaintext?
//
// It exists as a single function because the answer stopped being "decrypt its
// current version" when derived secrets arrived. Every reader — render, reveal,
// the GitHub push, the mirror API — has to expand a derivation the same way, and
// a reader that forgot would either fail on a secret with no versions or, worse,
// push an empty value. Having one implementation is what makes "a derived value
// cannot drift from its inputs" true everywhere rather than in the paths someone
// remembered to update.
package resolve

import (
	"fmt"

	"github.com/Einlanzerous/signet/internal/derive"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// Value returns sec's plaintext, expanding it if it is derived.
func Value(st *store.Store, key []byte, sec *store.Secret) (string, error) {
	if sec.Derived() {
		origin := derive.Ref{Project: sec.Project, Name: sec.Name}
		return derive.Resolve(origin, sec.Derivation, Lookup(st, key))
	}
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		return "", err
	}
	if cur == nil {
		return "", fmt.Errorf("secret %s/%s has no versions", sec.Project, sec.Name)
	}
	plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, err)
	}
	return string(plain), nil
}

// Lookup adapts the store to derive's resolver.
//
// A secret that exists but holds no version is reported Missing rather than as
// an empty value. Those are different facts and only one of them is safe: an
// empty string would compose silently into a DSN and deploy a half-configured
// container, which is the failure mode this whole feature is trying to make
// impossible rather than relocate.
func Lookup(st *store.Store, key []byte) derive.Lookup {
	return func(ref derive.Ref) (derive.Entry, error) {
		sec, err := st.GetSecret(ref.Project, ref.Name)
		if err != nil {
			return derive.Entry{}, err
		}
		if sec == nil {
			return derive.Entry{Missing: true}, nil
		}
		if sec.Derived() {
			// Handed back unexpanded: derive owns the recursion, because it is
			// the only place holding the path needed to name a cycle.
			return derive.Entry{Derivation: sec.Derivation}, nil
		}
		cur, err := st.CurrentVersion(sec.ID)
		if err != nil {
			return derive.Entry{}, err
		}
		if cur == nil {
			return derive.Entry{Missing: true}, nil
		}
		plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
		if err != nil {
			return derive.Entry{}, fmt.Errorf("%s: %w", ref, err)
		}
		return derive.Entry{Value: string(plain)}, nil
	}
}
