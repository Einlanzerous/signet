// Package disclose records plaintext leaving the vault.
//
// It holds one rule: *a disclosure of a derived secret is a disclosure of its
// inputs*. A derived secret has no value of its own — it is composed at read
// time from other secrets — so whatever reads it has just read theirs, across
// projects, and an entry written only against the derived secret leaves those
// inputs' own ledgers silent about it.
//
// # Why this is a package and not a helper on a call site
//
// The rule belongs to the derivation graph, not to any one channel that reads
// it, and this repo has now rediscovered that five times: `reveal` (SGNT-18),
// `exec` (SGNT-32), `render`, the rendered-target push, and the GitHub PAT read
// in internal/ops (all three SGNT-34, the last found by review). Each time it
// was found as an unaudited read channel in a vault whose premise is that
// plaintext leaves only in audited ways.
//
// The count is load-bearing and was wrong here once already: this comment said
// "four" while `ops.ResolveGHToken` was a fifth, in the package whose stated
// purpose is that a new channel inherits the rule. If you add a channel, add it
// to this list — and if you find one missing from the list, it is a bug in the
// channel, not in the list.
//
// Stated once per channel it gets restated or forgotten. The traversal lives
// here so a fifth channel inherits it rather than reimplementing it — and so
// the answer to "does this new egress path record what it disclosed" is a
// question about one import rather than about four copies staying in step.
//
// # What stays the caller's
//
// The wording and the classification do. What an investigator needs differs
// between a reveal to a terminal, an injection into a process, a file written
// to disk and a blob sealed into a GitHub secret, and so does the event kind —
// the disclosure channels share KindSecretReveal so one query answers "what
// disclosed this value", while a push is a KindSyncPush and belongs with its
// siblings. Only the traversal is not negotiable, and so only the traversal is
// not the caller's to get wrong.
package disclose

import (
	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
)

// Inputs records rec against every secret sec transitively derives from.
//
// rec is a template. Its SecretID is set per input and anything the caller left
// there is overwritten — the point of the call is that the caller does not know
// which secrets these are, which is the same reason the traversal is not theirs
// to write. Everything else, including Details and TargetID, is used as given.
//
// A non-derived secret has no inputs and this is a no-op, so a caller need not
// ask whether it is dealing with a derivation before recording one. That is
// deliberate: the check is exactly the thing a caller forgets.
//
// It stops at the first append that fails rather than continuing. A ledger that
// recorded some of a disclosure and not the rest, with nothing to say which,
// answers `audit --secret` with a confident partial truth; the caller's error
// path is a better place for that than this loop is.
func Inputs(st *store.Store, sec *store.Secret, rec store.AuditRecord) error {
	inputs, err := resolve.Inputs(st, sec)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		rec.SecretID = in.ID
		if _, err := st.AppendAudit(rec); err != nil {
			return err
		}
	}
	return nil
}
