package ops

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

func newVault(t *testing.T) (*store.Store, []byte) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return st, key
}

// putSecret stores value under project/name with an optional RFC3339 expiry.
func putSecret(t *testing.T, st *store.Store, key []byte, project, name, value, expiresAt string) {
	t.Helper()
	nonce, ct, err := vault.Encrypt(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret(project, name, "", false, expiresAt)
		if err != nil {
			return store.AuditRecord{}, err
		}
		if _, err := m.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), "test"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.set", SecretID: sec.ID, Details: "test fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func countAudit(t *testing.T, st *store.Store) int {
	t.Helper()
	n, err := st.CountAudit()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestResolveGHTokenPrefersEnv(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "from-vault", "")
	before := countAudit(t, st)

	tok, err := ResolveGHToken(st, key, "from-env", "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "from-env" || tok.Source != TokenFromEnv {
		t.Fatalf("env token not preferred: %+v", tok)
	}
	// The vault was never opened, so nothing should have been recorded against
	// it: an entry here would report a decrypt that did not happen.
	if got := countAudit(t, st); got != before {
		t.Fatalf("env path wrote %d audit entries", got-before)
	}
}

func TestResolveGHTokenFallsBackToVault(t *testing.T) {
	st, key := newVault(t)
	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_vaulted", expires)

	tok, err := ResolveGHToken(st, key, "", "cli:test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "ghp_vaulted" || tok.Source != TokenFromVault {
		t.Fatalf("vault fallback: %+v", tok)
	}
	if tok.ExpiresAt != expires {
		t.Fatalf("expiry not carried: %q want %q", tok.ExpiresAt, expires)
	}

	// The read is plaintext leaving the vault and has to be in the ledger as
	// such, attributed to the caller that asked for it.
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 newest entry, got %d", len(entries))
	}
	e := entries[0]
	if e.EventKind != store.KindSecretReveal || e.Actor != "cli:test" || e.Action != "secret.read" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if !strings.Contains(e.Details, GHTokenProject+"/"+GHTokenName) {
		t.Fatalf("entry does not name the secret read: %q", e.Details)
	}
	// The value itself must never reach the ledger.
	if strings.Contains(e.Details, "ghp_vaulted") {
		t.Fatalf("audit entry leaked the token: %q", e.Details)
	}
	ok, _, _, err := st.VerifyAudit()
	if err != nil || !ok {
		t.Fatalf("chain broken after fallback read: ok=%v err=%v", ok, err)
	}
}

func TestResolveGHTokenExpired(t *testing.T) {
	st, key := newVault(t)
	expired := time.Now().Add(-24 * time.Hour).UTC()
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_dead", expired.Format(time.RFC3339))
	before := countAudit(t, st)

	tok, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err == nil {
		t.Fatalf("expired token resolved: %+v", tok)
	}
	if !strings.Contains(err.Error(), expired.Format("2006-01-02")) {
		t.Fatalf("error does not name the expiry date: %v", err)
	}
	if tok.Value != "" {
		t.Fatalf("value returned alongside error: %q", tok.Value)
	}
	// Refused before the decrypt: nothing was revealed, so nothing is recorded.
	if got := countAudit(t, st); got != before {
		t.Fatalf("expired path wrote %d audit entries", got-before)
	}
}

// An expiry signet cannot read is not an expiry — it must not silently become
// "expired" and block a sync with a live credential.
func TestResolveGHTokenUnparseableExpiry(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_ok", "not-a-date")

	tok, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "ghp_ok" {
		t.Fatalf("unparseable expiry blocked the read: %+v", tok)
	}
}

func TestResolveGHTokenAbsent(t *testing.T) {
	st, key := newVault(t)

	_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err == nil {
		t.Fatal("empty vault resolved a token")
	}
	// The message has to say both halves were checked, or it reads as the old
	// "set the env var" failure and sends the caller back to a shell wrapper.
	for _, want := range []string{"SIGNET_GITHUB_TOKEN", GHTokenProject + "/" + GHTokenName} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}

func TestResolveGHTokenNoVersions(t *testing.T) {
	st, key := newVault(t)
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret(GHTokenProject, GHTokenName, "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: sec.ID, Details: "no versions",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err == nil || !strings.Contains(err.Error(), "no versions") {
		t.Fatalf("want no-versions error, got %v", err)
	}
}

// An empty stored value would otherwise be sealed into an Authorization header
// and come back as an unexplained 401.
func TestResolveGHTokenEmptyValue(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "", "")

	_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("want empty-value error, got %v", err)
	}
}
