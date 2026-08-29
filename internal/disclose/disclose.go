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
// it, and this repo has now rediscovered that six times:
//
//	reveal                    SGNT-18
//	exec                      SGNT-32
//	render                    SGNT-34
//	the single-secret push    SGNT-34 (PushSecret, found by review)
//	the rendered-target push  SGNT-34 (PushRender)
//	the GitHub PAT read       SGNT-34 (ops.ResolveGHToken, found by review)
//
// The two push halves are listed separately because they were two separate
// gaps, found and fixed separately: PushRender recorded no SecretID at all,
// while PushSecret recorded one and skipped the derivation. auditPushedInputs
// binds both.
//
// Each was an unaudited read channel in a vault whose premise is that plaintext
// leaves only in audited ways.
//
// All six cite their own direct entry by ledger SEQUENCE — `(reveal #N)`,
// `(exec #N)`, `(render #N)`, `(push #N)`, `(read #N)`. A digest or a
// provenance was tried first and is not a join key: both are functions of the
// VALUE, so a secret pushed on every deploy with nothing rotating between them
// wrote byte-identical rows against its inputs for ever. The sequence is the
// only thing that names a delivery rather than a value.
//
// The count is load-bearing and has now been wrong here twice — "four" while
// ops.ResolveGHToken was a fifth, then "five" while PushSecret was a sixth, in
// the package whose stated purpose is that a new channel inherits the rule. So
// read the list in one direction only: **a channel missing from it is a bug in
// the list, not evidence that the channel is not one.** The earlier wording
// said the opposite, which would have told a maintainer auditing coverage to
// treat a correctly-audited PushSecret as broken.
//
// Stated once per channel it gets restated or forgotten. The traversal lives
// here so a new channel inherits it rather than reimplementing it — and so the
// answer to "does this new egress path record what it disclosed" is a question
// about one import rather than about copies staying in step.
//
// No counts in that sentence, deliberately. It was written when there were
// four, and was still saying "a fifth" and "four copies" two corrections later
// — nine lines below a paragraph telling the reader a wrong count is a bug
// report. The table above is the count; prose that repeats it only goes stale
// somewhere the reader has been told to trust it.
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
