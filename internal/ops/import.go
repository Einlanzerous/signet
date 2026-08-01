// Package ops holds vault operations shared by the CLI and tests.
package ops

import (
	"fmt"

	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// ImportResult summarizes an env-file import.
type ImportResult struct {
	Created   int
	Updated   int
	Unchanged int
	Keys      []string
}

// ImportEnv imports every pair of the env file at path into project's secrets,
// creating a new version only when the value actually changed, and upserts a
// file target covering the imported keys. role is the normalized identity
// behind actor, recorded on each audit entry.
func ImportEnv(st *store.Store, key []byte, project, scope, path, actor string, role store.ActorRole) (ImportResult, error) {
	var res ImportResult
	pairs, err := envfile.ParseFile(path)
	if err != nil {
		return res, err
	}
	for _, p := range pairs {
		res.Keys = append(res.Keys, p.Key)
		sec, err := st.GetSecret(project, p.Key)
		if err != nil {
			return res, err
		}
		outcome := store.OutcomeCreated
		create := sec == nil
		if !create {
			cur, err := st.CurrentVersion(sec.ID)
			if err != nil {
				return res, err
			}
			if cur != nil {
				plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
				if err != nil {
					return res, err
				}
				if string(plain) == p.Value {
					res.Unchanged++
					continue
				}
			}
			outcome = store.OutcomeUpdated
		}
		nonce, ct, err := vault.Encrypt(key, []byte(p.Value))
		if err != nil {
			return res, err
		}
		// One transaction per key: the secret, its version and the entry
		// recording the import land together or not at all. Keys already
		// processed keep their entries — the import is per-key, and a failure
		// partway through leaves a ledger that says exactly how far it got.
		if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
			target := sec
			if create {
				created, err := m.CreateSecret(project, p.Key, scope, false, "")
				if err != nil {
					return store.AuditRecord{}, err
				}
				target = created
			}
			v, err := m.AddVersion(target.ID, nonce, ct, vault.VersionHash(nonce, ct), actor)
			if err != nil {
				return store.AuditRecord{}, err
			}
			return store.AuditRecord{
				Actor: actor, Action: "secret.import", SecretID: target.ID,
				Details:   fmt.Sprintf("imported %s/%s from %s · version %d #%s", project, p.Key, path, v.VersionNo, v.VHash),
				EventKind: store.KindSecretWrite, ActorRole: role,
				Status: &store.AuditStatus{Outcome: outcome},
			}, nil
		}); err != nil {
			return res, err
		}
		if create {
			res.Created++
		} else {
			res.Updated++
		}
	}
	// Registering the file target is a change to where this project's secrets
	// are delivered, so it is recorded like any other — `target rm` audits the
	// reverse, and an unaudited create against an audited remove would leave the
	// ledger showing detaches of targets it never saw attached.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		t, outcome, err := m.UpsertFileTarget(project, path, res.Keys, "0600")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: actor, Action: "target.file", TargetID: t.ID,
			Details:   fmt.Sprintf("%s → %s (%d keys)", project, path, len(res.Keys)),
			EventKind: store.KindTargetConfig, ActorRole: role,
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	}); err != nil {
		return res, err
	}
	return res, nil
}
