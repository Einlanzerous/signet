package sync

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// PushResult records the outcome of pushing one gh-actions target.
type PushResult struct {
	TargetID string `json:"target_id"`
	Repo     string `json:"repo"`
	Secret   string `json:"secret_name"`
	State    string `json:"state"` // in sync | error
	Note     string `json:"note,omitempty"`
	Err      string `json:"error,omitempty"`
	// Hint is the fix for a failure signet could attribute to a cause — a
	// repository missing from the PAT's grant list, most often. It accompanies
	// Err rather than replacing it: the ledger keeps the transport detail, and
	// the operator gets the sentence that names the next action.
	Hint string `json:"hint,omitempty"`
	// AuditErr reports a push that happened but could not be written to the
	// ledger. It is surfaced rather than swallowed: an unrecorded mutation of a
	// live destination is precisely what this vault must never do quietly.
	AuditErr string `json:"audit_error,omitempty"`
	// StateErr reports a push that happened but whose outcome could not be
	// written to the target row, so its recorded sync state is now stale.
	StateErr string `json:"state_error,omitempty"`
}

// recordPush writes the push's outcome to the target row and appends its ledger
// entry. Neither failure undoes the push — the destination has already changed —
// so both are reported on the result and logged instead of being discarded.
//
// A dropped state write is not cosmetic: last_pushed_version_id is what GHState
// compares against to decide whether a destination has drifted, so a silent
// failure here leaves the target reading "in sync" against a version it no
// longer holds, and nothing later corrects it.
func recordPush(st *store.Store, res *PushResult, rec store.AuditRecord, state, lastErr string, prov *store.PushProvenance, pushedAt string) {
	if err := st.UpdateTargetPush(res.TargetID, state, lastErr, prov, pushedAt); err != nil {
		res.StateErr = err.Error()
		log.Printf("target state write failed for %s: %v — the push happened but %s still reads as its previous state",
			res.Repo, err, res.TargetID)
	}
	if _, err := st.AppendAudit(rec); err != nil {
		res.AuditErr = err.Error()
		log.Printf("audit append failed for %s %s: %v — destination changed but the ledger has no entry",
			rec.Action, res.Repo, err)
	}
}

// PushSecret seals the secret's current version and pushes it to every
// gh-actions target attached to it, recording state and audit entries. role is
// the normalized identity behind actor, carried into the audit chain.
func PushSecret(ctx context.Context, st *store.Store, key []byte, gh *GHClient, sec *store.Secret, actor string, role store.ActorRole) ([]PushResult, error) {
	// Derived secrets are expanded here rather than read from a version, so a
	// composed value pushed to GitHub is computed from the same inputs the local
	// render used. Going through resolve is what keeps those two answers from
	// being produced by two different pieces of code.
	plaintextStr, cur, err := resolve.Value(st, key, sec)
	if err != nil {
		return nil, err
	}
	plaintext := []byte(plaintextStr)

	// What the ledger cites, and what the target records as pushed.
	//
	// A derived secret has no version row, so there is no id to record and no
	// vhash to quote. Rather than synthesize one, the entry names the
	// provenance instead — a hash over the resolved value would look like the
	// vhash beside it in the log while meaning something else entirely (that
	// one is over ciphertext, which is nonce-randomized and not comparable
	// across encryptions), and two hashes wearing one label is a trap.
	// resolve.Value is the authority on whether a version exists: nil means the
	// secret is derived and has none. Re-querying here to find out was both a
	// second round-trip and an unchecked dereference away from a crash.
	prov := store.PushProvenance{}
	provenance := ""
	if cur != nil {
		prov.VersionID = cur.ID
		provenance = "version #" + cur.VHash
	} else {
		// A derived secret's currency is the digest of what was delivered.
		// Without recording it the target has nothing to compare and GHState
		// reports "in sync" forever, however far the inputs travel.
		prov.Digest = vault.ValueDigest(key, plaintextStr)
		provenance = "derived from " + sec.Derivation + " · #" + prov.Digest
	}
	targets, err := st.TargetsForSecret(sec.ID)
	if err != nil {
		return nil, err
	}

	var results []PushResult
	for _, t := range targets {
		if t.Kind != "gh-actions" {
			continue
		}
		cfg, err := t.GHConfig()
		if err != nil {
			return nil, err
		}
		res := PushResult{TargetID: t.ID, Repo: cfg.Repo, Secret: cfg.SecretName}

		// Out-of-band change detection before we overwrite. A confirmed
		// out-of-band change makes this push a reconciliation of a drifted
		// destination, not a routine fan-out — the ledger records it as such.
		kind := store.KindSyncPush
		if drift, derr := gh.CheckGHDrift(ctx, cfg.Repo, cfg.SecretName, t.LastPushedAt); derr == nil && drift == GHOutOfBand && t.LastPushedAt != "" {
			res.Note = "destination changed out-of-band since last push — re-sealing"
			kind = store.KindDriftReconcile
		}

		stat, err := pushOne(ctx, gh, cfg, plaintext)
		// Only record numbers that were actually observed: a request that never
		// got a response has no status, and an unattempted call has no latency.
		status := &store.AuditStatus{}
		if stat.HTTPStatus != 0 {
			status.HTTPStatus = store.Measured(stat.HTTPStatus)
		}
		if stat.Measured {
			status.LatencyMS = store.Measured(stat.LatencyMS)
		}
		if err != nil {
			res.State = "error"
			res.Err = err.Error()
			res.Hint = AccessHint(cfg.Repo, err)
			status.Outcome = store.OutcomeFailed
			recordPush(st, &res, store.AuditRecord{
				Actor: actor, Action: "sync.push.failed", SecretID: sec.ID, TargetID: t.ID,
				Details:   fmt.Sprintf("%s → %s/%s: %s", sec.Name, cfg.Repo, cfg.SecretName, err),
				EventKind: kind, ActorRole: role, Status: status,
			}, "error", err.Error(), nil, "")
		} else {
			res.State = "in sync"
			status.Outcome = store.OutcomeDelivered
			detail := fmt.Sprintf("sealed & pushed %s → %s · Actions secret %s · %s", sec.Name, cfg.Repo, cfg.SecretName, provenance)
			if res.Note != "" {
				detail += " (" + res.Note + ")"
			}
			recordPush(st, &res, store.AuditRecord{
				Actor: actor, Action: "sync.push", SecretID: sec.ID, TargetID: t.ID,
				Details: detail, EventKind: kind, ActorRole: role, Status: status,
			}, "in sync", "", &prov, nowRFC3339())
		}
		results = append(results, res)
	}
	return results, nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// pushOne seals and delivers one value, returning the transport stat of the
// call that determined the outcome: the failing request, or the PUT that
// delivered it. Sealing is local, so a seal failure reports no HTTP status.
func pushOne(ctx context.Context, gh *GHClient, cfg store.GHConfig, plaintext []byte) (CallStat, error) {
	pk, stat, err := gh.RepoPublicKey(ctx, cfg.Repo)
	if err != nil {
		return stat, err
	}
	sealed, err := Seal(pk.Key, plaintext)
	if err != nil {
		return CallStat{}, err
	}
	return gh.PutSecret(ctx, cfg.Repo, cfg.SecretName, sealed, pk.KeyID)
}
