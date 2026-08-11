package resolve

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

func newStore(t *testing.T) (*store.Store, []byte) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "signet.db"))
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

func put(t *testing.T, st *store.Store, key []byte, project, name, value string) {
	t.Helper()
	nonce, ct, err := vault.Encrypt(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret(project, name, "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		if _, err := m.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), "test", store.Minted); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "set", SecretID: sec.ID,
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func derived(t *testing.T, st *store.Store, project, name, tmpl string) {
	t.Helper()
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret(project, name, "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		if err := m.SetDerivation(sec.ID, tmpl); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "derive", SecretID: sec.ID,
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func names(secs []store.Secret) map[string]bool {
	out := map[string]bool{}
	for _, s := range secs {
		out[s.Project+"/"+s.Name] = true
	}
	return out
}

// Derivations chain, so a rotation's report has to follow them. Naming only the
// direct reader under-reports what the write changed — which is the failure
// this feature exists to prevent, reproduced in the tool meant to reveal it.
func TestDependentsFollowsChains(t *testing.T) {
	st, key := newStore(t)
	put(t, st, key, "csrv", "PW", "x")
	derived(t, st, "drydock", "DSN", "u:{{csrv/PW}}@h")
	derived(t, st, "drydock", "WRAPPED", "[{{DSN}}]")
	derived(t, st, "other", "DEEP", "<{{drydock/WRAPPED}}>")
	derived(t, st, "elsewhere", "UNRELATED", "{{csrv/SOMETHING_ELSE}}")

	deps, err := Dependents(st, "csrv", "PW")
	if err != nil {
		t.Fatal(err)
	}
	got := names(deps)
	for _, want := range []string{"drydock/DSN", "drydock/WRAPPED", "other/DEEP"} {
		if !got[want] {
			t.Errorf("rotation report omits %s; got %v", want, got)
		}
	}
	if got["elsewhere/UNRELATED"] {
		t.Error("report names a secret that does not read this one")
	}
}

// A diamond must not report the shared node twice, and a cycle must not hang —
// Dependents runs on rotation paths, which cannot afford either.
func TestDependentsHandlesDiamondsAndCycles(t *testing.T) {
	st, key := newStore(t)
	put(t, st, key, "p", "BASE", "x")
	derived(t, st, "p", "LEFT", "{{BASE}}")
	derived(t, st, "p", "RIGHT", "{{BASE}}")
	derived(t, st, "p", "JOIN", "{{LEFT}}+{{RIGHT}}")

	deps, err := Dependents(st, "p", "BASE")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Errorf("diamond reported %d dependents, want 3 distinct: %v", len(deps), names(deps))
	}

	derived(t, st, "c", "A", "{{c/B}}")
	derived(t, st, "c", "B", "{{c/A}}")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := Dependents(st, "c", "A"); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Dependents did not terminate on a cyclic vault")
	}
}

// Inputs is what lets a reveal record disclosure against the ledgers of the
// secrets actually disclosed, so it has to reach the leaves through chains.
func TestInputsReachesLeavesThroughChains(t *testing.T) {
	st, key := newStore(t)
	put(t, st, key, "csrv", "PW", "x")
	put(t, st, key, "csrv", "USER", "u")
	derived(t, st, "drydock", "DSN", "{{csrv/USER}}:{{csrv/PW}}@h")
	derived(t, st, "drydock", "WRAPPED", "[{{DSN}}]")

	sec, err := st.GetSecret("drydock", "WRAPPED")
	if err != nil {
		t.Fatal(err)
	}
	ins, err := Inputs(st, sec)
	if err != nil {
		t.Fatal(err)
	}
	got := names(ins)
	for _, want := range []string{"drydock/DSN", "csrv/PW", "csrv/USER"} {
		if !got[want] {
			t.Errorf("Inputs omits %s, whose plaintext a reveal would print; got %v", want, got)
		}
	}
	if got["drydock/WRAPPED"] {
		t.Error("Inputs includes the secret itself")
	}
}

// Value is the authority on whether a version exists; callers rely on nil
// meaning "derived" rather than re-querying and dereferencing.
func TestValueReportsNoVersionForDerivedSecrets(t *testing.T) {
	st, key := newStore(t)
	put(t, st, key, "p", "PW", "hunter2")
	derived(t, st, "p", "DSN", "u:{{PW}}@h")

	sec, err := st.GetSecret("p", "DSN")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Current(st, key, sec)
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != "u:hunter2@h" {
		t.Errorf("got %q", r.Value)
	}
	if r.Version != nil {
		t.Error("a derived secret reported a version; callers treat non-nil as a stored value")
	}
	if r.Digest == "" {
		t.Error("a derived secret reported no digest; GHState reads an empty digest as 'not derived'")
	}

	stored, err := st.GetSecret("p", "PW")
	if err != nil {
		t.Fatal(err)
	}
	sr, err := Current(st, key, stored)
	if err != nil || sr.Version == nil {
		t.Errorf("a stored secret must report its version: cur=%v err=%v", sr.Version, err)
	}
	if sr.Digest != "" {
		t.Error("a stored secret reported a digest; exactly one of Version/Digest is meaningful")
	}
}
