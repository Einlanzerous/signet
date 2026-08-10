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
	"errors"
	"fmt"

	"github.com/Einlanzerous/signet/internal/derive"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// ErrNoVersion reports a stored secret that has no value yet — the state every
// secret passes through between creation and its first write.
//
// It is a sentinel rather than a boolean return because callers divide on it:
// render and status skip such a secret, while reveal and push must fail. A
// separate "does it have one?" query answered the same question a second time
// and cost every caller an extra round-trip per secret.
var ErrNoVersion = errors.New("no versions")

// Value returns sec's plaintext, expanding it if it is derived, together with
// the version the value came from.
//
// The version is nil for a derived secret — it has none, by construction — and
// callers must treat it as the authority on that rather than re-querying.
// Callers that tolerate a valueless secret check errors.Is(err, ErrNoVersion);
// every other error is a real failure.
func Value(st *store.Store, key []byte, sec *store.Secret) (string, *store.Version, error) {
	if sec.Derived() {
		origin := derive.Ref{Project: sec.Project, Name: sec.Name}
		v, err := derive.Resolve(origin, sec.Derivation, Lookup(st, key))
		return v, nil, err
	}
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		return "", nil, err
	}
	if cur == nil {
		return "", nil, fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, ErrNoVersion)
	}
	plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, err)
	}
	return string(plain), cur, nil
}

// Drift returns what store.Target.GHState needs in order to judge a
// destination: the current version for a stored secret, or the digest of the
// resolved value for a derived one, which has no version to compare.
//
// Every view that reports target state goes through this one function, because
// getting it wrong is silent and confident. GHState reads an empty digest as
// "not derived" and falls through to the version comparison; a derived secret
// whose derivation cannot resolve has neither, so passing both as empty makes
// GHState answer "in sync" about the one secret nobody can currently compute.
// The CLI and the mirror each reached that state independently — the mirror by
// way of a branch added to fix it elsewhere — which is what moved this out of
// both of them and into here.
func Drift(st *store.Store, key []byte, sec *store.Secret) (*store.Version, string, error) {
	v, cur, err := Value(st, key, sec)
	if err != nil {
		return nil, "", err
	}
	if sec.Derived() {
		return nil, vault.ValueDigest(key, v), nil
	}
	return cur, "", nil
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
