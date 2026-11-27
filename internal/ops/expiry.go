package ops

import (
	"errors"
	"fmt"
	"time"

	"github.com/Einlanzerous/signet/internal/store"
)

// ActionSetExpiry is the ledger verb for changing a secret's expiry on its own.
const ActionSetExpiry = "secret.set-expiry"

// ErrNoSecret is what SetExpiry returns for a secret that does not exist, so a
// caller can divide it from a store failure (the API answers 404 to one and 500
// to the other).
var ErrNoSecret = errors.New("no such secret")

// ParseExpiry converts a YYYY-MM-DD date to the RFC3339 form the store holds,
// and "" to "" (no expiry). It is the one date rule: `set`, `rotate`, `expire`
// and the API's set-expiry all go through it, so they cannot disagree about
// what a date is.
func ParseExpiry(date string) (string, error) {
	if date == "" {
		return "", nil
	}
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(time.RFC3339), nil
}

// SetExpiry sets a secret's expiry (RFC3339 from ParseExpiry, or "" to clear)
// without reading or writing its value, and records `secret.set-expiry` in the
// same transaction.
//
// It lives here because the CLI verb and the HTTP command were going to be two
// copies of one mutation and one audit record. The outcome is decided against
// the row re-read inside the transaction, not a snapshot from before it: a
// concurrent writer would otherwise make "unchanged" a claim about a state that
// is gone. The returned outcome is what the ledger recorded.
func SetExpiry(st *store.Store, project, name, expiresAt, actor string, role store.ActorRole) (store.Outcome, error) {
	sec, err := st.GetSecret(project, name)
	if err != nil {
		return "", err
	}
	if sec == nil {
		return "", fmt.Errorf("%w: %s/%s", ErrNoSecret, project, name)
	}
	outcome := store.OutcomeUpdated
	_, err = st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		fresh, err := m.GetSecretForUpdate(sec.ID)
		if err != nil {
			return store.AuditRecord{}, err
		}
		if fresh == nil {
			return store.AuditRecord{}, fmt.Errorf("%w: %s/%s disappeared", ErrNoSecret, project, name)
		}
		outcome = store.OutcomeUpdated
		if expiresAt == fresh.ExpiresAt {
			outcome = store.OutcomeUnchanged
		}
		if err := m.SetExpiry(sec.ID, expiresAt); err != nil {
			return store.AuditRecord{}, err
		}
		detail := project + "/" + name + ": cleared expiry"
		if expiresAt != "" {
			detail = fmt.Sprintf("%s/%s: expiry set to %s", project, name, expiresAt[:10])
		}
		return store.AuditRecord{
			Actor: actor, Action: ActionSetExpiry, SecretID: sec.ID, Details: detail,
			EventKind: store.KindPolicyChange, ActorRole: role,
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}
