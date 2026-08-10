// Package resolve answers one question for the whole codebase: what is this
// secret's current value, and what is known about it?
//
// The answer stopped being "decrypt its current version" when derived secrets
// arrived. Every reader — render, reveal, status, the GitHub push, the token
// lookup, the mirror API — has to expand a derivation the same way, and a
// reader that does it independently gets it wrong: first by never expanding at
// all, then by recomputing the drift inputs and reporting a secret it could not
// resolve as healthy.
//
// So Current returns everything at once and readers take what they need. The
// point is not convenience: it is that a reader cannot reach a different answer
// from the reader beside it, which is what makes "a derived value cannot drift
// from its inputs" a property of the system rather than of the paths someone
// remembered to update. If you find yourself computing a digest or fetching a
// version outside this package, that is the bug this package exists to prevent.
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

// Resolved is everything a reader can need about a secret's current value.
//
// It is one struct rather than several functions because every previous attempt
// to serve readers separately produced two implementations of one decision, and
// each time the second was wrong: first three readers that never expanded a
// derivation at all, then a mirror that recomputed the drift inputs itself and
// answered "in sync" for a secret it could not resolve. Returning everything at
// once means a reader takes the fields it needs and cannot arrive at a
// different answer from the reader beside it.
type Resolved struct {
	// Value is the plaintext, expanded if the secret is derived.
	Value string
	// Version is the row the value came from, nil for a derived secret — which
	// has none, by construction. Callers must treat this as the authority
	// rather than re-querying.
	Version *store.Version
	// Digest fingerprints a derived secret's resolved value, and is empty for a
	// stored one, whose currency is answered by Version. Exactly one of the two
	// is meaningful, which is the distinction store.Target.GHState reads.
	Digest string
}

// Current resolves a secret: the single read path for the whole codebase.
//
// Callers that tolerate a secret with no value yet check
// errors.Is(err, ErrNoVersion); every other error is a real failure. In
// particular a derivation that cannot be expanded never reports ErrNoVersion —
// derive names the missing input in its own message without wrapping, so a
// broken derivation cannot be mistaken for an unwritten secret and skipped.
func Current(st *store.Store, key []byte, sec *store.Secret) (Resolved, error) {
	if sec.Derived() {
		origin := derive.Ref{Project: sec.Project, Name: sec.Name}
		v, err := derive.Resolve(origin, sec.Derivation, Lookup(st, key))
		if err != nil {
			return Resolved{}, err
		}
		return Resolved{Value: v, Digest: vault.ValueDigest(key, v)}, nil
	}
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		return Resolved{}, err
	}
	if cur == nil {
		return Resolved{}, fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, ErrNoVersion)
	}
	plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return Resolved{}, fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, err)
	}
	return Resolved{Value: string(plain), Version: cur}, nil
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
