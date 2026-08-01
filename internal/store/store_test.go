package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The mutators live on Mutation, so fixtures are built through Mutate — the
// same audited path production code takes. Each helper therefore leaves one
// entry in the chain, which tests that count entries have to allow for.

func mustCreateSecret(t *testing.T, s *Store, project, name, scope string, generated bool) *Secret {
	t.Helper()
	var sec *Secret
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		created, err := m.CreateSecret(project, name, scope, generated, "")
		if err != nil {
			return AuditRecord{}, err
		}
		sec = created
		return testRecord(fmt.Sprintf("create %s/%s", project, name)), nil
	}); err != nil {
		t.Fatal(err)
	}
	return sec
}

func mustAddVersion(t *testing.T, s *Store, secretID string, nonce, ciphertext []byte, vhash string) *Version {
	t.Helper()
	var v *Version
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, err := m.AddVersion(secretID, nonce, ciphertext, vhash, "test")
		if err != nil {
			return AuditRecord{}, err
		}
		v = added
		return testRecord("version " + vhash), nil
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustAddGHTarget(t *testing.T, s *Store, secretID, repo, secretName string) *Target {
	t.Helper()
	var tgt *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, err := m.AddGHTarget(secretID, repo, secretName)
		if err != nil {
			return AuditRecord{}, err
		}
		tgt = added
		return testRecord("target " + repo), nil
	}); err != nil {
		t.Fatal(err)
	}
	return tgt
}

func mustUpsertFileTarget(t *testing.T, s *Store, project, path string, keys []string, mode string) (*Target, Outcome) {
	t.Helper()
	var tgt *Target
	var outcome Outcome
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, o, err := m.UpsertFileTarget(project, path, keys, mode)
		if err != nil {
			return AuditRecord{}, err
		}
		tgt, outcome = added, o
		return testRecord("file target " + path), nil
	}); err != nil {
		t.Fatal(err)
	}
	return tgt, outcome
}

// removeTarget returns the error rather than failing, because "removing
// something already gone must not succeed" is one of the things under test.
func removeTarget(s *Store, id string) error {
	_, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		if err := m.RemoveTarget(id); err != nil {
			return AuditRecord{}, err
		}
		return testRecord("remove " + id), nil
	})
	return err
}

func TestSecretVersioning(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "API_KEY", "inference", false)
	if cur, _ := s.CurrentVersion(sec.ID); cur != nil {
		t.Fatal("fresh secret should have no versions")
	}
	v1 := mustAddVersion(t, s, sec.ID, []byte("n1"), []byte("c1"), "aaaaaa")
	v2 := mustAddVersion(t, s, sec.ID, []byte("n2"), []byte("c2"), "bbbbbb")
	if v1.VersionNo != 1 || v2.VersionNo != 2 {
		t.Fatalf("version numbering: %d, %d", v1.VersionNo, v2.VersionNo)
	}
	cur, err := s.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.ID != v2.ID || cur.VHash != "bbbbbb" {
		t.Fatalf("current version wrong: %+v", cur)
	}
	// Uniqueness on (project, name).
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		_, err := m.CreateSecret("proj", "API_KEY", "", false, "")
		return testRecord("duplicate"), err
	}); err == nil {
		t.Fatal("duplicate (project, name) should fail")
	}
}

// testRecord is a minimal valid audit record for chain tests.
func testRecord(details string) AuditRecord {
	return AuditRecord{
		Actor: "tester", Action: "action", Details: details,
		EventKind: KindSecretWrite, ActorRole: RoleHuman,
	}
}

func TestAuditChainVerify(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(testRecord("entry")); err != nil {
			t.Fatal(err)
		}
	}
	ok, _, total, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || total != 5 {
		t.Fatalf("chain should verify: ok=%v total=%d", ok, total)
	}
}

func TestAuditAppendOnlyTriggers(t *testing.T) {
	s := testStore(t)
	if _, err := s.AppendAudit(testRecord("entry")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE audit_log SET details = 'tampered' WHERE seq = 1`); err == nil {
		t.Fatal("UPDATE on audit_log should be blocked by trigger")
	}
	if _, err := s.db.Exec(`DELETE FROM audit_log WHERE seq = 1`); err == nil {
		t.Fatal("DELETE on audit_log should be blocked by trigger")
	}
}

func TestAuditTamperBreaksChain(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(testRecord("entry")); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate an attacker editing the file directly: drop the guard triggers,
	// rewrite history, and check the chain catches it.
	if _, err := s.db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE audit_log SET details = 'rewritten' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	ok, badSeq, _, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if ok || badSeq != 2 {
		t.Fatalf("tamper not caught: ok=%v badSeq=%d", ok, badSeq)
	}
}

func TestFileTargetUpsertMergesKeys(t *testing.T) {
	s := testStore(t)
	t1, o1 := mustUpsertFileTarget(t, s, "proj", "/tmp/x/.env", []string{"B", "A"}, "0600")
	t2, o2 := mustUpsertFileTarget(t, s, "proj", "/tmp/x/.env", []string{"C", "A"}, "")
	if o1 != OutcomeCreated || o2 != OutcomeUpdated {
		t.Fatalf("outcomes should distinguish create from merge: %q then %q", o1, o2)
	}
	// Re-upserting keys it already has changes nothing, and must say so.
	if _, o3 := mustUpsertFileTarget(t, s, "proj", "/tmp/x/.env", []string{"A"}, ""); o3 != OutcomeUnchanged {
		t.Fatalf("no-op upsert should be unchanged, got %q", o3)
	}
	if t1.ID != t2.ID {
		t.Fatal("same path should upsert, not duplicate")
	}
	cfg, err := t2.FileConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"A", "B", "C"}
	if len(cfg.Keys) != 3 || cfg.Keys[0] != want[0] || cfg.Keys[1] != want[1] || cfg.Keys[2] != want[2] {
		t.Fatalf("merged keys wrong: %v", cfg.Keys)
	}
	if cfg.Mode != "0600" {
		t.Fatalf("mode lost on merge: %q", cfg.Mode)
	}
}

func TestGHTargetStateUpdates(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", false)
	tgt := mustAddGHTarget(t, s, sec.ID, "owner/repo", "KEY")
	if tgt.LastState != "never" {
		t.Fatalf("fresh target state: %q", tgt.LastState)
	}
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", "vid1", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	targets, err := s.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if targets[0].LastState != "in sync" || targets[0].LastPushedVersionID != "vid1" {
		t.Fatalf("push state not recorded: %+v", targets[0])
	}
	// Error keeps last pushed version.
	if err := s.UpdateTargetPush(tgt.ID, "error", "boom", "", ""); err != nil {
		t.Fatal(err)
	}
	targets, _ = s.TargetsForSecret(sec.ID)
	if targets[0].LastError != "boom" || targets[0].LastPushedVersionID != "vid1" {
		t.Fatalf("error state wrong: %+v", targets[0])
	}
}

func TestFindAndRemoveTargets(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", false)
	gh := mustAddGHTarget(t, s, sec.ID, "owner/repo", "KEY")
	// A second destination for the same secret: (repo, secret_name) is the
	// identifying pair, so a different name on the same repo is its own target.
	mustAddGHTarget(t, s, sec.ID, "owner/repo", "OTHER_NAME")
	file, _ := mustUpsertFileTarget(t, s, "proj", "/tmp/x/.env", []string{"KEY"}, "0600")

	found, err := s.FindGHTarget(sec.ID, "owner/repo", "KEY")
	if err != nil || found == nil || found.ID != gh.ID {
		t.Fatalf("gh lookup wrong: %+v err=%v", found, err)
	}
	if miss, err := s.FindGHTarget(sec.ID, "owner/repo", "NOPE"); err != nil || miss != nil {
		t.Fatalf("unknown secret_name should not match: %+v err=%v", miss, err)
	}
	if miss, err := s.FindGHTarget(sec.ID, "other/repo", "KEY"); err != nil || miss != nil {
		t.Fatalf("unknown repo should not match: %+v err=%v", miss, err)
	}
	if f, err := s.FindFileTarget("proj", "/tmp/x/.env"); err != nil || f == nil || f.ID != file.ID {
		t.Fatalf("file lookup wrong: %+v err=%v", f, err)
	}

	if err := removeTarget(s, gh.ID); err != nil {
		t.Fatal(err)
	}
	// Only that one went; the sibling destination survives.
	remaining, err := s.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("want 1 remaining gh target, got %d", len(remaining))
	}
	if cfg, _ := remaining[0].GHConfig(); cfg.SecretName != "OTHER_NAME" {
		t.Fatalf("removed the wrong target: %+v", cfg)
	}
	if gone, err := s.FindGHTarget(sec.ID, "owner/repo", "KEY"); err != nil || gone != nil {
		t.Fatalf("removed target still found: %+v", gone)
	}
	// Removing something already gone is an error, not a silent success.
	if err := removeTarget(s, gh.ID); err == nil {
		t.Fatal("removing a missing target should error")
	}
}

// TestRemovedTargetKeepsAuditHistory: the chain is append-only, so detaching a
// target must not disturb entries that reference it.
func TestRemovedTargetKeepsAuditHistory(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", false)

	var tgt *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, err := m.AddGHTarget(sec.ID, "owner/repo", "KEY")
		if err != nil {
			return AuditRecord{}, err
		}
		tgt = added
		return AuditRecord{
			Actor: "cli:test", Action: "target.add", SecretID: sec.ID, TargetID: added.ID,
			EventKind: KindTargetConfig, ActorRole: RoleHuman,
			Status: &AuditStatus{Outcome: OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		if err := m.RemoveTarget(tgt.ID); err != nil {
			return AuditRecord{}, err
		}
		return AuditRecord{
			Actor: "cli:test", Action: "target.rm", SecretID: sec.ID, TargetID: tgt.ID,
			EventKind: KindTargetConfig, ActorRole: RoleHuman,
			Status: &AuditStatus{Outcome: OutcomeRemoved},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListAudit(10, "")
	if err != nil {
		t.Fatal(err)
	}
	// Newest first: target.rm, target.add, then the fixture's secret creation.
	if len(entries) != 3 || entries[0].TargetID != tgt.ID || entries[1].TargetID != tgt.ID {
		t.Fatalf("audit history should still name the removed target: %+v", entries)
	}
	if ok, badSeq, _, err := s.VerifyAudit(); err != nil || !ok {
		t.Fatalf("chain broken after target removal: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// TestGHStateDerivesDrift pins the reason target state is computed rather than
// read back: last_state only ever records what the last push did, so a vault
// that has moved on since still reads "in sync" there.
func TestGHStateDerivesDrift(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
	v1 := mustAddVersion(t, s, sec.ID, []byte("n"), []byte("c"), "aaa")
	tgt := mustAddGHTarget(t, s, sec.ID, "owner/repo", "KEY")
	if got := tgt.GHState(v1); got != "never" {
		t.Fatalf("unpushed target: want never, got %q", got)
	}

	// Push v1: in sync, and last_state agrees.
	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", v1.ID, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	targets, _ := s.TargetsForSecret(sec.ID)
	if got := targets[0].GHState(v1); got != "in sync" {
		t.Fatalf("just pushed: want in sync, got %q", got)
	}

	// Vault moves on without a push. This is the case last_state cannot see.
	v2 := mustAddVersion(t, s, sec.ID, []byte("n2"), []byte("c2"), "bbb")
	targets, _ = s.TargetsForSecret(sec.ID)
	if targets[0].LastState != "in sync" {
		t.Fatalf("precondition: stored state should still read in sync, got %q", targets[0].LastState)
	}
	if got := targets[0].GHState(v2); got != "drift" {
		t.Fatalf("vault moved on: want drift, got %q", got)
	}

	// An error on the target outranks everything.
	if err := s.UpdateTargetPush(tgt.ID, "error", "boom", "", ""); err != nil {
		t.Fatal(err)
	}
	targets, _ = s.TargetsForSecret(sec.ID)
	if got := targets[0].GHState(v2); got != "error" {
		t.Fatalf("failed push: want error, got %q", got)
	}
}

// unrecordable is a record the chain will not accept: validate() rejects it for
// having no actor. It fails from inside the append, after the mutation has
// already written — the same position a real chain failure occupies.
var unrecordable = AuditRecord{}

// TestAuditFailureRollsBackMutation covers the whole mutating surface: when the
// ledger entry cannot be written, the change it was going to describe must not
// survive. A vault whose premise is a tamper-evident record of what happened
// cannot afford a change that happened with nothing saying so.
func TestAuditFailureRollsBackMutation(t *testing.T) {
	t.Run("create secret", func(t *testing.T) {
		s := testStore(t)
		if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
			if _, err := m.CreateSecret("proj", "KEY", "", true, ""); err != nil {
				return AuditRecord{}, err
			}
			return unrecordable, nil
		}); err == nil {
			t.Fatal("an unrecordable mutation should fail")
		}
		if sec, err := s.GetSecret("proj", "KEY"); err != nil || sec != nil {
			t.Fatalf("secret landed without a ledger entry: %+v err=%v", sec, err)
		}
	})

	t.Run("add version", func(t *testing.T) {
		s := testStore(t)
		sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
		if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
			if _, err := m.AddVersion(sec.ID, []byte("n"), []byte("c"), "aaa", "test"); err != nil {
				return AuditRecord{}, err
			}
			return unrecordable, nil
		}); err == nil {
			t.Fatal("an unrecordable mutation should fail")
		}
		// This is the rotation case: the value would have changed with nothing
		// in the chain to say it did.
		if cur, err := s.CurrentVersion(sec.ID); err != nil || cur != nil {
			t.Fatalf("version landed without a ledger entry: %+v err=%v", cur, err)
		}
	})

	t.Run("set expiry", func(t *testing.T) {
		s := testStore(t)
		sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
		if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
			if err := m.SetExpiry(sec.ID, "2027-01-01T00:00:00Z"); err != nil {
				return AuditRecord{}, err
			}
			return unrecordable, nil
		}); err == nil {
			t.Fatal("an unrecordable mutation should fail")
		}
		after, err := s.GetSecretByID(sec.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.ExpiresAt != "" {
			t.Fatalf("expiry landed without a ledger entry: %q", after.ExpiresAt)
		}
	})

	t.Run("add gh target", func(t *testing.T) {
		s := testStore(t)
		sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
		if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
			if _, err := m.AddGHTarget(sec.ID, "owner/repo", "KEY"); err != nil {
				return AuditRecord{}, err
			}
			return unrecordable, nil
		}); err == nil {
			t.Fatal("an unrecordable mutation should fail")
		}
		targets, err := s.TargetsForSecret(sec.ID)
		if err != nil || len(targets) != 0 {
			t.Fatalf("target landed without a ledger entry: %+v err=%v", targets, err)
		}
	})

	t.Run("remove target", func(t *testing.T) {
		s := testStore(t)
		sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
		tgt := mustAddGHTarget(t, s, sec.ID, "owner/repo", "KEY")
		if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
			if err := m.RemoveTarget(tgt.ID); err != nil {
				return AuditRecord{}, err
			}
			return unrecordable, nil
		}); err == nil {
			t.Fatal("an unrecordable mutation should fail")
		}
		// The worst case: a destination detached with no record of the detach.
		found, err := s.FindGHTarget(sec.ID, "owner/repo", "KEY")
		if err != nil || found == nil {
			t.Fatalf("target detached without a ledger entry: %+v err=%v", found, err)
		}
	})
}

// TestFailedMutationLeavesChainIntact: a rolled-back attempt must leave no gap
// or stub behind — the next entry links to the head as if nothing happened.
func TestFailedMutationLeavesChainIntact(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
	before, err := s.CountAudit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		if _, err := m.AddVersion(sec.ID, []byte("n"), []byte("c"), "aaa", "test"); err != nil {
			return AuditRecord{}, err
		}
		return unrecordable, nil
	}); err == nil {
		t.Fatal("an unrecordable mutation should fail")
	}
	mustAddVersion(t, s, sec.ID, []byte("n"), []byte("c"), "bbb")

	if n, err := s.CountAudit(); err != nil || n != before+1 {
		t.Fatalf("failed attempt left an entry behind: %d entries, want %d (err=%v)", n, before+1, err)
	}
	if ok, badSeq, _, err := s.VerifyAudit(); err != nil || !ok {
		t.Fatalf("chain broken after a rolled-back mutation: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
	// The version that did commit is version 1: the rolled-back one never
	// claimed a number.
	cur, err := s.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.VersionNo != 1 || cur.VHash != "bbb" {
		t.Fatalf("rolled-back version left a hole in the numbering: %+v", cur)
	}
}

// TestMutateValueWithholdsValueOnRollback: the point of returning the value
// instead of assigning a captured variable is that a rolled-back change hands
// back nothing. A caller that got the target back would be holding an id no row
// has.
func TestMutateValueWithholdsValueOnRollback(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "proj", "KEY", "", true)
	tgt, _, err := MutateValue(s, func(m *Mutation) (*Target, AuditRecord, error) {
		added, err := m.AddGHTarget(sec.ID, "owner/repo", "KEY")
		if err != nil {
			return nil, AuditRecord{}, err
		}
		return added, unrecordable, nil
	})
	if err == nil {
		t.Fatal("an unrecordable mutation should fail")
	}
	if tgt != nil {
		t.Fatalf("rolled-back mutation handed back a target that does not exist: %+v", tgt)
	}
}

// TestConcurrentFileTargetUpsertStaysSingle: the upsert decides between merge
// and insert by reading first. Run that read outside the transaction that acts
// on it and two importers of the same path both find nothing and both insert —
// there is no UNIQUE constraint to catch the second.
func TestConcurrentFileTargetUpsertStaysSingle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upsert.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const writers = 10
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			_, err := st.Mutate(func(m *Mutation) (AuditRecord, error) {
				if _, _, err := m.UpsertFileTarget("proj", "/tmp/x/.env", []string{fmt.Sprintf("K%d", i)}, "0600"); err != nil {
					return AuditRecord{}, err
				}
				return testRecord("upsert"), nil
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("upsert failed under contention: %v", err)
	}

	targets, err := a.FileTargetsForProject("proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("concurrent upserts of one path created %d targets, want 1", len(targets))
	}
	cfg, err := targets[0].FileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Keys) != writers {
		t.Fatalf("merge lost keys: %d of %d survived (%v)", len(cfg.Keys), writers, cfg.Keys)
	}
}

// TestConcurrentGHTargetAddStaysUnique: (repo, secret_name) uniqueness is
// enforced by a check, not a constraint, so the check has to run in the
// transaction that inserts. This is the shape both add-target call sites use.
func TestConcurrentGHTargetAddStaysUnique(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addtarget.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	sec := mustCreateSecret(t, a, "proj", "KEY", "", true)

	const writers = 10
	var wg sync.WaitGroup
	added := make(chan struct{}, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			_, err := st.Mutate(func(m *Mutation) (AuditRecord, error) {
				dup, err := m.FindGHTarget(sec.ID, "owner/repo", "KEY")
				if err != nil {
					return AuditRecord{}, err
				}
				if dup != nil {
					return AuditRecord{}, errors.New("already exists")
				}
				if _, err := m.AddGHTarget(sec.ID, "owner/repo", "KEY"); err != nil {
					return AuditRecord{}, err
				}
				return testRecord("target add"), nil
			})
			if err == nil {
				added <- struct{}{}
			}
		}(i)
	}
	wg.Wait()
	close(added)

	if n := len(added); n != 1 {
		t.Fatalf("%d writers believed they created the target, want 1", n)
	}
	targets, err := a.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("concurrent add-target created %d targets, want 1", len(targets))
	}
}

// TestConcurrentMutateKeepsChainIntact is the fork guard again, now that the
// mutation shares the append's transaction: the critical section is wider, and
// it still has to hold across processes. Version numbering doubles as the
// witness — MAX(version_no)+1 is now read inside the same transaction that
// writes it, so no two writers can claim the same number.
func TestConcurrentMutateKeepsChainIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent-mutate.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path) // a second handle stands in for a second process
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	sec := mustCreateSecret(t, a, "proj", "KEY", "", true)

	const writes = 20
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			_, err := st.Mutate(func(m *Mutation) (AuditRecord, error) {
				v, err := m.AddVersion(sec.ID, []byte("n"), []byte("c"), fmt.Sprintf("%06d", i), "test")
				if err != nil {
					return AuditRecord{}, err
				}
				return testRecord(fmt.Sprintf("version %d", v.VersionNo)), nil
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("mutation failed under contention: %v", err)
	}

	ok, badSeq, total, err := a.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("concurrent mutations forked the chain at seq %d", badSeq)
	}
	if want := writes + 1; total != want { // +1 for the secret's creation
		t.Fatalf("want %d entries, got %d", want, total)
	}
	cur, err := a.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.VersionNo != writes {
		t.Fatalf("version numbers collided or skipped: highest is %d, want %d", cur.VersionNo, writes)
	}
}
