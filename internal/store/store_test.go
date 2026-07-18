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

func TestAuditChainVerify(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit("tester", "action", "", "", "entry"); err != nil {
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
	if _, err := s.AppendAudit("tester", "action", "", "", "entry"); err != nil {
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
		if _, err := s.AppendAudit("tester", "action", "", "", "entry"); err != nil {
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
