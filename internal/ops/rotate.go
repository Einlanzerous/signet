package ops

import (
	"fmt"

	"github.com/Einlanzerous/signet/internal/store"
)

// Rotatable reports whether a secret may be rotated, and why not when it may
// not.
//
// It lives here because both the CLI verb and the HTTP command answer this
// question, and they were answering it from two copies. Two surfaces that
// refuse the same secret with different words teach an operator that the answer
// depends on which door they used — and the copies had already begun to drift.
//
// Derived is tested before Generated: a derived secret would otherwise fall
// into the externally-issued branch and be told to rotate "at the issuer",
// advice for a value that has no issuer and no stored form.
func Rotatable(sec *store.Secret) error {
	if sec.Derived() {
		return fmt.Errorf("%s/%s is derived from %s — it has no value of its own to rotate; rotate one of its inputs instead",
			sec.Project, sec.Name, sec.Derivation)
	}
	if !sec.Generated {
		return fmt.Errorf("%s/%s is externally issued — signet can fan out a new value but cannot mint one; "+
			"rotate it at the issuer, then `signet set --project %s --name %s`",
			sec.Project, sec.Name, sec.Project, sec.Name)
	}
	return nil
}
