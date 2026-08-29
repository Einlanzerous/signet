package sync

import (
	"fmt"
	"log"

	"github.com/Einlanzerous/signet/internal/disclose"
	"github.com/Einlanzerous/signet/internal/store"
)

// ── Recording what a push disclosed, as opposed to what it did (SGNT-34) ────
//
// A push entry says a destination was written. It does not, on its own, answer
// the question asked from the credential's side — `signet audit --secret <ref>`,
// "where has this value been sent" — because that query filters on secret_id.
//
// PushSecret's entries have always carried one. Two paths beside it did not,
// and both were found while checking whether `sync` shared `render`'s gap:
//
//   - a rendered target delivers many secrets' plaintext as one blob, and
//     recorded only the TargetID. This is the larger exposure of the two — the
//     construct-server render carries 95 keys — and every one of them was
//     invisible from its own ledger.
//   - a *derived* secret pushed by PushSecret records against itself and not
//     against the inputs whose plaintext its value carries. Same defect
//     SGNT-18 closed for `reveal`, in a channel that sends the value off-box.
//
// Both write additional entries rather than changing the existing ones. The
// per-target entry is the right record of the push and something audits
// renders by target; these are a second index on the same event, not a
// replacement for the first.

// noteAuditErr records a ledger write that failed after the destination had
// already changed.
//
// It never returns an error, matching recordPush: the push happened, and
// nothing here can undo it. The first failure is kept rather than the last,
// because a later one is usually the same cause repeating and the earliest is
// the one that says where the ledger stopped being complete.
func noteAuditErr(res *PushResult, err error, what string) {
	if res.AuditErr == "" {
		res.AuditErr = err.Error()
	}
	log.Printf("audit append failed for %s %s: %v — destination changed but the ledger has no entry",
		what, res.Repo, err)
}

// auditPushedInputs records a push against the inputs of a derived secret,
// whose plaintext its delivered value carries.
//
// The traversal is internal/disclose's; this binds it to the push's actor,
// role, kind and target. rec deliberately carries the *push's own* kind rather
// than KindSecretReveal — KindSyncPush normally, KindDriftReconcile when the
// destination had changed out of band — because an input's ledger should show
// the disclosure as the same class of event the derived secret's does.
func auditPushedInputs(st *store.Store, res *PushResult, sec *store.Secret, rec store.AuditRecord) {
	if err := disclose.Inputs(st, sec, rec); err != nil {
		noteAuditErr(res, err, rec.Action+" (derivation inputs)")
	}
}

// auditRenderedKeys records a rendered-target push against every secret whose
// plaintext the delivered blob carried.
//
// One entry per key, as `render` and `exec` do, and for the same reason: the
// query these serve filters on secret_id, so an entry naming only the project
// answers it empty for every secret in that project. Each is kept short and
// cites the blob's digest, which is what ties it back to the target entry that
// holds the full account — the key count, the scope, and any keys the push
// added.
//
// Failures here do not fail the push. It has already happened, the blob is at
// the destination, and a caller that treated an incomplete ledger as a failed
// delivery would report the opposite of the truth.
func auditRenderedKeys(st *store.Store, res *PushResult, t *store.Target, cfg store.GHRenderConfig,
	kind store.EventKind, actor string, role store.ActorRole, digest string) {

	for _, k := range cfg.Keys {
		sec, err := st.GetSecret(t.Project, k)
		if err != nil {
			noteAuditErr(res, err, "sync.push (key "+k+")")
			continue
		}
		if sec == nil {
			// RenderBlob refuses a push whose keys the vault cannot supply, so
			// reaching here means the secret was removed between the render and
			// this loop. The value still went out; say so rather than dropping
			// the only trace of it.
			noteAuditErr(res, fmt.Errorf("no secret %s/%s backs a key this push delivered", t.Project, k),
				"sync.push (key "+k+")")
			continue
		}
		rec := store.AuditRecord{
			Actor: actor, Action: "sync.push", SecretID: sec.ID, TargetID: t.ID,
			Details: fmt.Sprintf("plaintext delivered in the %s render → %s · #%s",
				t.Project, cfg.Destination(), digest),
			EventKind: kind, ActorRole: role,
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}
		if _, err := st.AppendAudit(rec); err != nil {
			noteAuditErr(res, err, "sync.push (key "+k+")")
			continue
		}
		// The digest travels with it. Without it every push of this blob writes
		// an input entry identical to the last, so `audit --secret <input>`
		// returns N rows that cannot be told apart — while the direct entry
		// three lines up cites the digest for exactly this reason. Round 1 of
		// the review on #43 found this asymmetry on the CLI render path; it was
		// fixed there and left here, which is the fix-at-the-instance shape
		// REVIEW.md names first.
		rec.Details = fmt.Sprintf("value delivered to %s in the %s render of %s/%s, which derives from it · #%s",
			cfg.Destination(), t.Project, sec.Project, sec.Name, digest)
		auditPushedInputs(st, res, sec, rec)
	}
}
