package sync

import (
	"context"
	"fmt"
	"log"
	"time"

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
func recordPush(st *store.Store, res *PushResult, rec store.AuditRecord, state, lastErr, versionID, pushedAt string) {
	if err := st.UpdateTargetPush(res.TargetID, state, lastErr, versionID, pushedAt); err != nil {
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
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, fmt.Errorf("secret %s/%s has no versions", sec.Project, sec.Name)
	}
	plaintext, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", sec.Project, sec.Name, err)
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
			}, "error", err.Error(), "", "")
		} else {
			res.State = "in sync"
			status.Outcome = store.OutcomeDelivered
			detail := fmt.Sprintf("sealed & pushed %s → %s · Actions secret %s · version #%s", sec.Name, cfg.Repo, cfg.SecretName, cur.VHash)
			if res.Note != "" {
				detail += " (" + res.Note + ")"
			}
			recordPush(st, &res, store.AuditRecord{
				Actor: actor, Action: "sync.push", SecretID: sec.ID, TargetID: t.ID,
				Details: detail, EventKind: kind, ActorRole: role, Status: status,
			}, "in sync", "", cur.ID, nowRFC3339())
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
