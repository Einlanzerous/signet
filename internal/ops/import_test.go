package ops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

func TestImportIdempotent(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, _ := vault.GenerateKey()

	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("A=1\nB=two words\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := ImportEnv(st, key, "proj", "", env, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 2 || res.Updated != 0 || res.Unchanged != 0 {
		t.Fatalf("first import: %+v", res)
	}

	// Re-import unchanged: no new versions.
	res, err = ImportEnv(st, key, "proj", "", env, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Updated != 0 || res.Unchanged != 2 {
		t.Fatalf("re-import: %+v", res)
	}
	sec, _ := st.GetSecret("proj", "A")
	cur, _ := st.CurrentVersion(sec.ID)
	if cur.VersionNo != 1 {
		t.Fatalf("unchanged value re-versioned: %d", cur.VersionNo)
	}

	// Change one value: exactly one update.
	if err := os.WriteFile(env, []byte("A=1\nB=changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = ImportEnv(st, key, "proj", "", env, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Updated != 1 || res.Unchanged != 1 {
		t.Fatalf("changed import: %+v", res)
	}
	secB, _ := st.GetSecret("proj", "B")
	curB, _ := st.CurrentVersion(secB.ID)
	if curB.VersionNo != 2 {
		t.Fatalf("changed value should be version 2, got %d", curB.VersionNo)
	}
	plain, err := vault.Decrypt(key, curB.Nonce, curB.Ciphertext)
	if err != nil || string(plain) != "changed" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}

	// One file target, covering both keys.
	targets, _ := st.FileTargetsForProject("proj")
	if len(targets) != 1 {
		t.Fatalf("want 1 file target, got %d", len(targets))
	}
	cfg, _ := targets[0].FileConfig()
	if len(cfg.Keys) != 2 {
		t.Fatalf("file target keys: %v", cfg.Keys)
	}

	// Registering the file target is audited like any other target change, and
	// says which of the three imports actually altered it. `target rm` records
	// the detach; an unrecorded attach would leave the ledger showing removals
	// of targets it never saw arrive.
	entries, err := st.ListAudit(100, "")
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []store.Outcome
	for i := len(entries) - 1; i >= 0; i-- { // oldest first
		if entries[i].EventKind == store.KindTargetConfig {
			if entries[i].TargetID != targets[0].ID {
				t.Fatalf("target entry names the wrong target: %+v", entries[i])
			}
			outcomes = append(outcomes, entries[i].Status.Outcome)
		}
	}
	want := []store.Outcome{store.OutcomeCreated, store.OutcomeUnchanged, store.OutcomeUnchanged}
	if len(outcomes) != len(want) {
		t.Fatalf("want %d file-target entries, got %d (%v)", len(want), len(outcomes), outcomes)
	}
	for i := range want {
		if outcomes[i] != want[i] {
			t.Fatalf("file-target outcomes %v, want %v", outcomes, want)
		}
	}
	if ok, badSeq, _, err := st.VerifyAudit(); err != nil || !ok {
		t.Fatalf("chain broken after imports: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}
