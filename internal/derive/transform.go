package derive

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/Einlanzerous/signet/internal/vault"
)

// A transform is a named function applied to one reference's value inside a
// template: {{drydock/PASSWORD | scrypt}}.
//
// The constraint that shapes this file is that a derived secret is computed on
// every read and never stored, so a transform has to give the same output for
// the same input every time. One that does not — the obvious case being any
// password hash with a random salt — changes the value on every render, and
// `render --check` then reports permanent drift. That is the failure derived
// secrets exist to remove, reintroduced from the other direction and *loud*,
// which trains an operator to skip the drift report on the run where it is
// right.
//
// So the property is enforced where a transform is declared, not where it is
// first run. Parse accepts a name only if it is in the registry below, and the
// registry holds only transforms that are deterministic — a suite test applies
// every entry repeatedly and compares. A template naming one that is not cannot be
// saved, so the second render is not where anyone finds out. The one way to be
// recognised but unusable is `refused`, which exists so the operator asking for
// bcrypt is told why they cannot have it instead of being told the name is
// unknown.
type transform struct {
	// apply computes the output for one input. Its signature carries everything
	// it is meant to depend on — the input, the deriving secret and the vault key
	// — so a transform reaching for anything else stands out in review; the suite
	// test is what actually checks the result.
	apply func(c transformCtx, input string) (string, error)
	// refused, when set, is why this name cannot be declared. Parse returns it.
	refused string
}

// transformCtx is what a transform may depend on besides its input. Both fields
// are stable across renders of an unchanged vault.
type transformCtx struct {
	// origin is the secret whose template holds the transform. A salt bound to
	// it means two secrets hashing the same value do not produce the same hash.
	origin Ref
	// key is the vault's master key, the only source of a salt.
	key []byte
}

// transforms is the whole vocabulary. Adding to it is a decision about
// determinism, and TestEveryRegisteredTransformIsDeterministic holds each entry
// to it.
//
// There is deliberately no bare `sha256`: a plain hash of secret material is
// brute-forceable from wherever it lands (see vault.ValueDigest for why signet
// keys its own), and a caller who wants a password hash wants scrypt.
var transforms = map[string]transform{
	// Standard alphabet with padding: what a Kubernetes Secret's data field and
	// an HTTP basic-auth header both carry.
	"base64": {apply: func(_ transformCtx, in string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte(in)), nil
	}},
	"hex": {apply: func(_ transformCtx, in string) (string, error) {
		return hex.EncodeToString([]byte(in)), nil
	}},
	"scrypt": {apply: scryptHash},
	"bcrypt": {refused: "bcrypt draws its salt from crypto/rand inside the library and takes none from the caller, " +
		"so its output differs on every read and `render --check` would report permanent drift. " +
		"Use scrypt, which signet salts deterministically"},
}

// Transforms returns the names that can be declared, sorted. The unknown-name
// error lists these, and so does the usage text, beside Refused.
func Transforms() []string { return names(func(t transform) bool { return t.refused == "" }) }

// Refused returns the names that are recognised but cannot be declared, sorted.
// It is the other half of the registry: usage text built from Transforms alone
// would say nothing about a name an operator is likely to try, so both halves
// are generated and a test holds every entry to being in exactly one of them.
func Refused() []string { return names(func(t transform) bool { return t.refused != "" }) }

func names(keep func(transform) bool) []string {
	var out []string
	for name, t := range transforms {
		if keep(t) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// lookupTransform returns the named transform, or an error saying why it cannot
// be used. Every path from a template to a transform goes through here, so a
// stored template that names one the registry no longer allows fails the same
// way a freshly typed one does.
func lookupTransform(name, tmpl string) (transform, error) {
	t, ok := transforms[name]
	switch {
	case !ok:
		return transform{}, fmt.Errorf("derivation %q: unknown transform %q — available: %s",
			tmpl, name, strings.Join(Transforms(), ", "))
	case t.refused != "":
		return transform{}, fmt.Errorf("derivation %q: transform %q cannot be used: %s", tmpl, name, t.refused)
	}
	return t, nil
}

// scrypt parameters, matching what Drydock's own hash-password script writes —
// N=16384, r=8, p=1, a 16-byte salt and a 32-byte key — because the output is
// meant to be read back by `verifyPassword` there. The parameters are in the
// hash string, so raising them later leaves every existing hash verifying.
const (
	scryptN       = 16384
	scryptR       = 8
	scryptP       = 1
	scryptKeyLen  = 32
	scryptSaltLen = 16
)

// scryptHash returns `scrypt$N$r$p$<salt b64>$<hash b64>` of the input.
//
// The salt is vault.KeyedSalt over the deriving secret's identity and the input
// value. That is the piece of this that is a decision rather than a lookup:
//
//   - It is deterministic, which is the requirement. Same vault, same output.
//   - It changes when the password does. A salt fixed per secret would survive a
//     rotation unchanged, which is the weakening SGNT-22 names; this one cannot.
//   - It is unpredictable without the master key, so putting the value in its own
//     salt gives an attacker holding the finished hash nothing to precompute
//     from — they learn a salt they could not have derived, and are where they
//     would be with a random one.
//   - Nothing needs to be stored. The salt is written into the hash string, which
//     is where a verifier reads it from.
//
// What it costs: the hash is a function of the master key, so a vault
// re-created under a different key renders a different one. Signet has no verb
// that changes the key; a restore under the same key changes nothing.
func scryptHash(c transformCtx, input string) (string, error) {
	if len(c.key) == 0 {
		// Refused rather than salted with nothing. An unkeyed salt would still
		// be deterministic, and would make every hash of the same value the
		// same string in every vault — a rainbow table with extra steps.
		return "", fmt.Errorf("scrypt has no vault key to salt with")
	}
	if input == "" {
		// A well-formed hash of the empty password is a hash that accepts an
		// empty login, and it would render without complaint.
		return "", fmt.Errorf("scrypt of an empty value — the input has no value to hash")
	}
	salt := vault.KeyedSalt(c.key, scryptSaltLen, "scrypt", c.origin.String(), input)
	dk, err := scrypt.Key([]byte(input), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("scrypt: %w", err)
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", scryptN, scryptR, scryptP,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(dk)), nil
}
