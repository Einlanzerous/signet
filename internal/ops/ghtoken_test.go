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

// The root credential is read for more than one reason now. An audit of it is
// worth less if a preflight is recorded as a push, so the entry states which
// it was.
func TestResolveGHTokenRecordsItsPurpose(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_vaulted", "")

	if _, err := ResolveGHTokenFor(st, key, "", "cli:test", store.RoleHuman, PurposePreflight); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 newest entry, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Details, string(PurposePreflight)) {
		t.Fatalf("entry does not state the preflight purpose: %q", entries[0].Details)
	}
	if strings.Contains(entries[0].Details, string(PurposeSync)) {
		t.Fatalf("preflight recorded as a sync: %q", entries[0].Details)
	}

	// The default path still says what it always said.
	if _, err := ResolveGHToken(st, key, "", "cli:test", store.RoleHuman); err != nil {
		t.Fatal(err)
	}
	entries, err = st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entries[0].Details, string(PurposeSync)) {
		t.Fatalf("sync read does not state its purpose: %q", entries[0].Details)
	}
}

func TestResolveGHTokenExpired(t *testing.T) {
	st, key := newVault(t)
	// Midnight UTC of yesterday, stored the way `set --expires` stores a date.
	expired := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
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

// An expiry is a date, and GitHub honors the PAT through all of it. Refusing at
// midnight would take a working credential away for its whole last day.
func TestResolveGHTokenLastDayStillValid(t *testing.T) {
	st, key := newVault(t)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_lastday", today.Format(time.RFC3339))

	tok, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err != nil {
		t.Fatalf("token expiring today refused: %v", err)
	}
	if tok.Value != "ghp_lastday" {
		t.Fatalf("got %+v", tok)
	}
}

// Values arrive from `printf | signet set` and from CRLF env files, and the
// token goes straight into an Authorization header.
func TestResolveGHTokenTrimsWhitespace(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "  ghp_padded\r\n", "")

	tok, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "ghp_padded" {
		t.Fatalf("whitespace not trimmed: %q", tok.Value)
	}
}

// The environment is consulted twice — SIGNET_GITHUB_TOKEN, then SIGNET_PAT —
// and config collapses both into one value before this package sees it. A
// message naming only the first sends whoever exported the second to check a
// variable they never used.
func TestResolveGHTokenFailuresNameEveryLookupPath(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, st *store.Store, key []byte)
	}{
		// The two states in which nothing was found anywhere. The expired and
		// empty cases below are excluded on purpose: there the credential was
		// located, so reciting the search would say nothing useful.
		{"nothing in the vault", func(*testing.T, *store.Store, []byte) {}},
		{"registered with no value", func(t *testing.T, st *store.Store, key []byte) {
			mustCreateBare(t, st)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, key := newVault(t)
			tc.setup(t, st, key)
			_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
			if err == nil {
				t.Fatal("resolved a token it should have refused")
			}
			msg := err.Error()
			if !strings.Contains(msg, GHTokenProject+"/"+GHTokenName) {
				t.Fatalf("error omits the vault lookup path: %v", err)
			}
			// The environment half is asserted against what is left once the two
			// places that legitimately spell SIGNET_PAT without being the variable
			// are removed: the vault ref (signet/SIGNET_PAT) and the remediation
			// command (--name SIGNET_PAT). Searching the whole message for
			// "SIGNET_PAT" passes on a message that never mentions the environment
			// at all, which is exactly the regression this guards.
			env := strings.ReplaceAll(msg, ghTokenFix, "")
			env = strings.ReplaceAll(env, GHTokenProject+"/"+GHTokenName, "")
			for _, name := range []string{"SIGNET_GITHUB_TOKEN", "SIGNET_PAT"} {
				if !strings.Contains(env, name) {
					t.Fatalf("error does not name the %s environment lookup: %v", name, err)
				}
			}
		})
	}
}

// An env var holding only whitespace is not a credential. Treating it as one
// skips the vault that does hold the PAT, and spends the run on a 401 naming
// neither the variable nor the whitespace in it.
func TestResolveGHTokenIgnoresWhitespaceOnlyEnvToken(t *testing.T) {
	st, key := newVault(t)
	putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_vaulted", "")

	tok, err := ResolveGHToken(st, key, " \r\n\t ", "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Source != TokenFromVault || tok.Value != "ghp_vaulted" {
		t.Fatalf("whitespace env token shadowed the vault: %+v", tok)
	}

	// A real value keeps arriving from the environment, trimmed.
	tok, err = ResolveGHToken(st, key, " ghp_from_env\n", "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Source != TokenFromEnv || tok.Value != "ghp_from_env" {
		t.Fatalf("env token not used or not trimmed: %+v", tok)
	}
}

// Each of these messages is read at the moment a sync stopped working, so each
// has to carry the command that fixes it.
func TestResolveGHTokenFailuresNameTheFix(t *testing.T) {
	yesterday := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1).Format(time.RFC3339)
	cases := []struct {
		name  string
		setup func(t *testing.T, st *store.Store, key []byte)
	}{
		{"absent", func(*testing.T, *store.Store, []byte) {}},
		{"expired", func(t *testing.T, st *store.Store, key []byte) {
			putSecret(t, st, key, GHTokenProject, GHTokenName, "ghp_dead", yesterday)
		}},
		{"empty", func(t *testing.T, st *store.Store, key []byte) {
			putSecret(t, st, key, GHTokenProject, GHTokenName, "", "")
		}},
		{"no versions", func(t *testing.T, st *store.Store, key []byte) {
			mustCreateBare(t, st)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, key := newVault(t)
			tc.setup(t, st, key)
			_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
			if err == nil {
				t.Fatal("resolved a token it should have refused")
			}
			if !strings.Contains(err.Error(), "signet set --project signet --name SIGNET_PAT --expires") {
				t.Fatalf("no remediation command in: %v", err)
			}
		})
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

// mustCreateBare registers the secret without ever storing a value: a `set`
// that failed partway, not a corrupt vault.
func mustCreateBare(t *testing.T, st *store.Store) {
	t.Helper()
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
}

func TestResolveGHTokenNoVersions(t *testing.T) {
	st, key := newVault(t)
	mustCreateBare(t, st)

	_, err := ResolveGHToken(st, key, "", "test", store.RoleHuman)
	if err == nil || !strings.Contains(err.Error(), "no value stored") {
		t.Fatalf("want no-value error, got %v", err)
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

// The token lookup is named in resolve's package doc as a reader that goes
// through it, and for a long time did not. A derived PAT reported "has no value
// stored" and told the operator to run `signet set` — which refuses derived
// secrets, so the instruction could not be followed.
func TestGHTokenResolvesADerivedPAT(t *testing.T) {
	st, key := newVault(t)

	putSecret(t, st, key, "signet", "PAT_PART", "ghp_realtoken", "")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret("signet", "SIGNET_PAT", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		if err := m.SetDerivation(sec.ID, "{{PAT_PART}}"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "derive", SecretID: sec.ID,
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveGHTokenFor(st, key, "", "test", store.RoleHuman, PurposePreflight)
	if err != nil {
		t.Fatalf("derived PAT did not resolve: %v", err)
	}
	if got.Value != "ghp_realtoken" {
		t.Errorf("got %q", got.Value)
	}
}
