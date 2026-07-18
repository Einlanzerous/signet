package sync

import (
	"context"
	"fmt"
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
}

// PushSecret seals the secret's current version and pushes it to every
// gh-actions target attached to it, recording state and audit entries.
func PushSecret(ctx context.Context, st *store.Store, key []byte, gh *GHClient, sec *store.Secret, actor string) ([]PushResult, error) {
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

		// Out-of-band change detection before we overwrite.
		if drift, derr := gh.CheckGHDrift(ctx, cfg.Repo, cfg.SecretName, t.LastPushedAt); derr == nil && drift == GHOutOfBand && t.LastPushedAt != "" {
			res.Note = "destination changed out-of-band since last push — re-sealing"
		}

		if err := pushOne(ctx, gh, cfg, plaintext); err != nil {
			res.State = "error"
			res.Err = err.Error()
			_ = st.UpdateTargetPush(t.ID, "error", err.Error(), "", "")
			_, _ = st.AppendAudit(actor, "sync.push.failed", sec.ID, t.ID,
				fmt.Sprintf("%s → %s/%s: %s", sec.Name, cfg.Repo, cfg.SecretName, err))
		} else {
			res.State = "in sync"
			pushedAt := nowRFC3339()
			_ = st.UpdateTargetPush(t.ID, "in sync", "", cur.ID, pushedAt)
			detail := fmt.Sprintf("sealed & pushed %s → %s · Actions secret %s · version #%s", sec.Name, cfg.Repo, cfg.SecretName, cur.VHash)
			if res.Note != "" {
				detail += " (" + res.Note + ")"
			}
			_, _ = st.AppendAudit(actor, "sync.push", sec.ID, t.ID, detail)
		}
		results = append(results, res)
	}
	return results, nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func pushOne(ctx context.Context, gh *GHClient, cfg store.GHConfig, plaintext []byte) error {
	pk, err := gh.RepoPublicKey(ctx, cfg.Repo)
	if err != nil {
		return err
	}
	sealed, err := Seal(pk.Key, plaintext)
	if err != nil {
		return err
	}
	return gh.PutSecret(ctx, cfg.Repo, cfg.SecretName, sealed, pk.KeyID)
}
