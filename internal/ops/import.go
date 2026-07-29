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
		if sec == nil {
			if sec, err = st.CreateSecret(project, p.Key, scope, false, ""); err != nil {
				return res, err
			}
			res.Created++
		} else {
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
			res.Updated++
			outcome = store.OutcomeUpdated
		}
		nonce, ct, err := vault.Encrypt(key, []byte(p.Value))
		if err != nil {
			return res, err
		}
		v, err := st.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), actor)
		if err != nil {
			return res, err
		}
		if _, err := st.AppendAudit(store.AuditRecord{
			Actor: actor, Action: "secret.import", SecretID: sec.ID,
			Details:   fmt.Sprintf("imported %s/%s from %s · version %d #%s", project, p.Key, path, v.VersionNo, v.VHash),
			EventKind: store.KindSecretWrite, ActorRole: role,
			Status: &store.AuditStatus{Outcome: outcome},
		}); err != nil {
			return res, err
		}
	}
	if _, err := st.UpsertFileTarget(project, path, res.Keys, "0600"); err != nil {
		return res, err
	}
	return res, nil
}
