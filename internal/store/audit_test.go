package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMigrationUpgradesExistingVault applies migration 002 to a database built
// at the previous schema version and holding real entries — the deployed-vault
// case. The pre-existing chain must still verify afterwards, and new structured
// entries must chain onto it.
func TestMigrationUpgradesExistingVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Build the vault at schema version 1 only, and write an entry through the
	// column list that existed then.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	ts := now()
	const details = "master key + database created"
	hash := chainHashV1(genesisHash, ts, "cli:magos", "vault.init", "", "", details)
	if _, err := db.Exec(`
        INSERT INTO audit_log (ts, actor, action, details, prev_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?)`, ts, "cli:magos", "vault.init", details, genesisHash, hash); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen through the store: migration 002 applies in place.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("migrating an existing vault: %v", err)
	}
	defer s.Close()

	if ok, badSeq, total, err := s.VerifyAudit(); err != nil || !ok || total != 1 {
		t.Fatalf("pre-existing chain must survive migration: ok=%v badSeq=%d total=%d err=%v", ok, badSeq, total, err)
	}
	if _, err := s.AppendAudit(testRecord("post-migration entry")); err != nil {
		t.Fatal(err)
	}
	if ok, badSeq, total, err := s.VerifyAudit(); err != nil || !ok || total != 2 {
		t.Fatalf("new entry must chain onto the migrated one: ok=%v badSeq=%d total=%d err=%v", ok, badSeq, total, err)
	}
	// The append-only guards must still be in force after the ALTER TABLEs.
	if _, err := s.db.Exec(`UPDATE audit_log SET details = 'tampered' WHERE seq = 1`); err == nil {
		t.Fatal("append-only UPDATE trigger lost during migration")
	}
	if _, err := s.db.Exec(`DELETE FROM audit_log WHERE seq = 1`); err == nil {
		t.Fatal("append-only DELETE trigger lost during migration")
	}
}

// insertLegacyEntry writes a row exactly as the pre-structured-ledger code did:
// hash version 1, no event_kind/actor_role/status. It is how these tests stand
// in for a chain that already exists in a deployed vault.
func insertLegacyEntry(t *testing.T, s *Store, prev, details string) string {
	t.Helper()
	ts := now()
	hash := chainHashV1(prev, ts, "cli:legacy", "secret.create", "", "", details)
	if _, err := s.db.Exec(`
        INSERT INTO audit_log (ts, actor, action, secret_id, target_id, details, prev_hash, hash, hash_version)
        VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, 1)`,
		ts, "cli:legacy", "secret.create", details, prev, hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

// TestLegacyChainSurvivesStructuredUpgrade is the migration-safety test: a
// vault that already holds v1 entries must keep verifying after the structured
// fields land, and new v2 entries must chain onto the old ones.
func TestLegacyChainSurvivesStructuredUpgrade(t *testing.T) {
	s := testStore(t)
	prev := genesisHash
	for i := 0; i < 3; i++ {
		prev = insertLegacyEntry(t, s, prev, "legacy entry")
	}
	if ok, badSeq, total, err := s.VerifyAudit(); err != nil || !ok || total != 3 {
		t.Fatalf("legacy-only chain must verify: ok=%v badSeq=%d total=%d err=%v", ok, badSeq, total, err)
	}

	// Append structured entries on top of the legacy tail.
	for i := 0; i < 2; i++ {
		if _, err := s.AppendAudit(AuditRecord{
			Actor: "api:switchyard", Action: "rotate", EventKind: KindRotation,
			ActorRole: RoleRuleEngine, Status: &AuditStatus{Outcome: OutcomeRotated},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ok, badSeq, total, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || total != 5 {
		t.Fatalf("mixed v1/v2 chain must verify: ok=%v badSeq=%d total=%d", ok, badSeq, total)
	}

	entries, err := s.ListAudit(50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
	// Newest first: structured entries carry the new fields, legacy ones do not.
	if entries[0].EventKind != KindRotation || entries[0].ActorRole != RoleRuleEngine {
		t.Fatalf("structured entry lost its fields: %+v", entries[0])
	}
	if entries[0].Status == nil || entries[0].Status.Outcome != OutcomeRotated {
		t.Fatalf("structured entry lost its status: %+v", entries[0].Status)
	}
	if entries[0].HashVersion != hashV2 {
		t.Fatalf("new entry should be hash version %d, got %d", hashV2, entries[0].HashVersion)
	}
	last := entries[len(entries)-1]
	if last.EventKind != "" || last.ActorRole != "" || last.Status != nil {
		t.Fatalf("legacy entry should carry no structured fields: %+v", last)
	}
	if last.HashVersion != hashV1 {
		t.Fatalf("legacy entry should stay hash version %d, got %d", hashV1, last.HashVersion)
	}
}

// TestLegacyEntryJSONOmitsStructuredFields guards the mirror contract: an older
// entry must serialize exactly as before so existing consumers keep parsing it,
// and so a consumer can tell "absent" from "empty".
func TestLegacyEntryJSONOmitsStructuredFields(t *testing.T) {
	s := testStore(t)
	insertLegacyEntry(t, s, genesisHash, "legacy entry")
	entries, err := s.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"event_kind", "actor_role", "status"} {
		if strings.Contains(string(blob), field) {
			t.Fatalf("legacy entry must omit %q, got %s", field, blob)
		}
	}
}

// TestTamperOnStructuredFieldsBreaksChain proves the new fields are covered by
// the hash — the whole point of putting them in a hash-chained ledger rather
// than a side table.
func TestTamperOnStructuredFieldsBreaksChain(t *testing.T) {
	tamper := map[string]string{
		"event_kind": `UPDATE audit_log SET event_kind = 'secret_write' WHERE seq = 2`,
		"actor_role": `UPDATE audit_log SET actor_role = 'human' WHERE seq = 2`,
		"status":     `UPDATE audit_log SET status = '{"outcome":"delivered"}' WHERE seq = 2`,
	}
	for field, stmt := range tamper {
		t.Run(field, func(t *testing.T) {
			s := testStore(t)
			for i := 0; i < 3; i++ {
				if _, err := s.AppendAudit(AuditRecord{
					Actor: "healer", Action: ActionHealerRestart, EventKind: KindHealerAction,
					ActorRole: RoleHealer, Status: &AuditStatus{Outcome: OutcomeAutoResolved},
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			ok, badSeq, _, err := s.VerifyAudit()
			if err != nil {
				t.Fatal(err)
			}
			if ok || badSeq != 2 {
				t.Fatalf("tampering with %s not caught: ok=%v badSeq=%d", field, ok, badSeq)
			}
		})
	}
}

// TestStructuredFieldsOnV1RowRejected covers the downgrade attack: v1 hashing
// does not cover the structured fields, so a row that claims version 1 while
// carrying them is unverifiable and must not pass.
func TestStructuredFieldsOnV1RowRejected(t *testing.T) {
	s := testStore(t)
	insertLegacyEntry(t, s, genesisHash, "legacy entry")
	if _, err := s.db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE audit_log SET actor_role = 'daemon' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	if ok, badSeq, _, err := s.VerifyAudit(); err != nil || ok || badSeq != 1 {
		t.Fatalf("v1 row carrying structured fields must fail: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// TestUnknownHashVersionRejected ensures an unrecognized scheme is treated as
// broken rather than silently trusted.
func TestUnknownHashVersionRejected(t *testing.T) {
	s := testStore(t)
	if _, err := s.AppendAudit(testRecord("entry")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE audit_log SET hash_version = 99 WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	if ok, badSeq, _, err := s.VerifyAudit(); err != nil || ok || badSeq != 1 {
		t.Fatalf("unknown hash version must fail: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// TestAuditRecordValidation keeps untyped or mislabeled entries out of the
// chain at the point of append.
func TestAuditRecordValidation(t *testing.T) {
	s := testStore(t)
	cases := map[string]AuditRecord{
		"missing actor":   {Action: "a", EventKind: KindRender, ActorRole: RoleHuman},
		"missing action":  {Actor: "a", EventKind: KindRender, ActorRole: RoleHuman},
		"missing kind":    {Actor: "a", Action: "a", ActorRole: RoleHuman},
		"unknown kind":    {Actor: "a", Action: "a", EventKind: "teleport", ActorRole: RoleHuman},
		"missing role":    {Actor: "a", Action: "a", EventKind: KindRender},
		"unknown role":    {Actor: "a", Action: "a", EventKind: KindRender, ActorRole: "wizard"},
		"unknown outcome": {Actor: "a", Action: "a", EventKind: KindRender, ActorRole: RoleHuman, Status: &AuditStatus{Outcome: "vibes"}},
	}
	for name, rec := range cases {
		if _, err := s.AppendAudit(rec); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if n, err := s.CountAudit(); err != nil || n != 0 {
		t.Fatalf("rejected records must not reach the chain: n=%d err=%v", n, err)
	}
}

// TestHealerLedgerEntries covers the watcher/healer path end to end: the
// helpers append to the same chain, and the 7-day aggregate that backs the
// healer-actions tile counts by outcome.
func TestHealerLedgerEntries(t *testing.T) {
	s := testStore(t)
	if _, err := s.AppendWatcherEvent("watcher", "watcher.health-check", "postgres healthy",
		&AuditStatus{Outcome: OutcomeVerifiedHealthy}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.AppendHealerAction("healer", ActionHealerRestart, "restarted postgres", OutcomeAutoResolved); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AppendHealerAction("healer", ActionHealerRollback, "rolled back caddy", OutcomeReverted); err != nil {
		t.Fatal(err)
	}
	if ok, badSeq, _, err := s.VerifyAudit(); err != nil || !ok {
		t.Fatalf("healer entries must chain cleanly: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}

	since := time.Now().UTC().AddDate(0, 0, -7).Format(time.RFC3339)
	counts, err := s.CountAuditKindSince(KindHealerAction, since)
	if err != nil {
		t.Fatal(err)
	}
	if counts[OutcomeAutoResolved] != 3 || counts[OutcomeReverted] != 1 {
		t.Fatalf("healer 7d counts wrong: %+v", counts)
	}
	// The watcher event is a different kind and must not be counted.
	if len(counts) != 2 {
		t.Fatalf("healer counts should hold only healer outcomes: %+v", counts)
	}

	// A window that starts after the entries were written excludes them.
	future := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)
	if counts, err := s.CountAuditKindSince(KindHealerAction, future); err != nil || len(counts) != 0 {
		t.Fatalf("future window should be empty: %+v err=%v", counts, err)
	}
}

// TestAuditStatusRoundTrip checks the numeric status fields survive storage and
// that an absent value stays absent rather than becoming a misleading zero.
func TestAuditStatusRoundTrip(t *testing.T) {
	s := testStore(t)
	if _, err := s.AppendAudit(AuditRecord{
		Actor: "api:switchyard", Action: "sync.push", EventKind: KindSyncPush, ActorRole: RoleDispatcher,
		Status: &AuditStatus{Outcome: OutcomeDelivered, HTTPStatus: 204, LatencyMS: 84},
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	got := entries[0].Status
	if got == nil || got.Outcome != OutcomeDelivered || got.HTTPStatus != 204 || got.LatencyMS != 84 {
		t.Fatalf("status round-trip wrong: %+v", got)
	}
	if got.RetriedFrom != 0 || got.RetriedTo != 0 {
		t.Fatalf("unset retry fields should stay zero: %+v", got)
	}
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "retried_from") {
		t.Fatalf("unset retry fields must be omitted, got %s", blob)
	}
}
