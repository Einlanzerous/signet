package store

import (
	"path/filepath"
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

func TestSecretVersioning(t *testing.T) {
	s := testStore(t)
	sec, err := s.CreateSecret("proj", "API_KEY", "inference", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if cur, _ := s.CurrentVersion(sec.ID); cur != nil {
		t.Fatal("fresh secret should have no versions")
	}
	v1, err := s.AddVersion(sec.ID, []byte("n1"), []byte("c1"), "aaaaaa", "test")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.AddVersion(sec.ID, []byte("n2"), []byte("c2"), "bbbbbb", "test")
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := s.CreateSecret("proj", "API_KEY", "", false, ""); err == nil {
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
	t1, err := s.UpsertFileTarget("proj", "/tmp/x/.env", []string{"B", "A"}, "0600")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := s.UpsertFileTarget("proj", "/tmp/x/.env", []string{"C", "A"}, "")
	if err != nil {
		t.Fatal(err)
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
	sec, _ := s.CreateSecret("proj", "KEY", "", false, "")
	tgt, err := s.AddGHTarget(sec.ID, "owner/repo", "KEY")
	if err != nil {
		t.Fatal(err)
	}
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
	sec, _ := s.CreateSecret("proj", "KEY", "", false, "")
	gh, err := s.AddGHTarget(sec.ID, "owner/repo", "KEY")
	if err != nil {
		t.Fatal(err)
	}
	// A second destination for the same secret: (repo, secret_name) is the
	// identifying pair, so a different name on the same repo is its own target.
	if _, err := s.AddGHTarget(sec.ID, "owner/repo", "OTHER_NAME"); err != nil {
		t.Fatal(err)
	}
	file, err := s.UpsertFileTarget("proj", "/tmp/x/.env", []string{"KEY"}, "0600")
	if err != nil {
		t.Fatal(err)
	}

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

	if err := s.RemoveTarget(gh.ID); err != nil {
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
	if err := s.RemoveTarget(gh.ID); err == nil {
		t.Fatal("removing a missing target should error")
	}
}

// TestRemovedTargetKeepsAuditHistory: the chain is append-only, so detaching a
// target must not disturb entries that reference it.
func TestRemovedTargetKeepsAuditHistory(t *testing.T) {
	s := testStore(t)
	sec, _ := s.CreateSecret("proj", "KEY", "", false, "")
	tgt, err := s.AddGHTarget(sec.ID, "owner/repo", "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAudit(AuditRecord{
		Actor: "cli:test", Action: "target.add", SecretID: sec.ID, TargetID: tgt.ID,
		EventKind: KindTargetConfig, ActorRole: RoleHuman,
		Status: &AuditStatus{Outcome: OutcomeCreated},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveTarget(tgt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAudit(AuditRecord{
		Actor: "cli:test", Action: "target.rm", SecretID: sec.ID, TargetID: tgt.ID,
		EventKind: KindTargetConfig, ActorRole: RoleHuman,
		Status: &AuditStatus{Outcome: OutcomeRemoved},
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAudit(10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].TargetID != tgt.ID || entries[1].TargetID != tgt.ID {
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
	sec, _ := s.CreateSecret("proj", "KEY", "", true, "")
	v1, err := s.AddVersion(sec.ID, []byte("n"), []byte("c"), "aaa", "test")
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := s.AddGHTarget(sec.ID, "owner/repo", "KEY")
	if err != nil {
		t.Fatal(err)
	}
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
	v2, err := s.AddVersion(sec.ID, []byte("n2"), []byte("c2"), "bbb", "test")
	if err != nil {
		t.Fatal(err)
	}
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
