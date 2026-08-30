package sync

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// refuseWrites installs a trigger that aborts every write of one kind to one
// table, so a real push meets a real write failure at the point the production
// code handles it.
//
// A trigger rather than a mock: the thing under test is what PushRender does
// when the database says no, and the only honest way to ask is to have the
// database say no. `database is locked` under a concurrent signet is the
// production shape — the 95-key construct-server render is the case SGNT-44 was
// filed about — and it arrives at exactly this seam.
func refuseWrites(t *testing.T, dbPath, name, event, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TRIGGER " + name + " BEFORE " + event + " ON " + table +
		" BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END;"); err != nil {
		t.Fatal(err)
	}
}

// fixtureAt builds the render fixture at a path the test keeps, so a second
// connection can reach the same database.
func fixtureAt(t *testing.T, baseURL string, keys []string, values map[string]string) (*store.Store, []byte, *store.Target, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	st, key, target := renderFixtureAt(t, path, baseURL, keys, values)
	return st, key, target, path
}

// A push that reached GitHub and could not be written to the ledger sets
// AuditErr rather than failing the push. This is the condition SGNT-44's CLI
// change reports, and it is asserted here so that change is answering something
// that happens rather than a field that exists.
//
// The push itself still succeeds — that is the point. The destination has the
// new blob; only signet's account of it is missing, and nothing about the
// result other than this field says so.
func TestALedgerFailureIsReportedOnAnOtherwiseSuccessfulPush(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target, path := fixtureAt(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)

	refuseWrites(t, path, "no_audit", "INSERT", "audit_log")

	res, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatalf("a ledger failure took the push down with it: %v", err)
	}
	// The delivery happened. An operator told this failed would re-run a push
	// that has already changed a live environment.
	if res.State != "in sync" {
		t.Fatalf("the push did not land: %+v", res)
	}
	if len(*delivered) == 0 {
		t.Fatal("nothing reached the destination, so this is not the case under test")
	}
	if res.AuditErr == "" {
		t.Fatal("a push whose ledger write failed reports nothing on the result — " +
			"the only trace would be a log line on stderr")
	}
	if !strings.Contains(res.AuditErr, "disk I/O error") {
		t.Errorf("AuditErr does not carry what the database said: %q", res.AuditErr)
	}
}

// The same for StateErr, which SGNT-44 asks be handled alongside rather than
// left for later. Its cost is different: the ledger keeps its entry, but the
// target row still holds the previous push's fingerprint, so GHState compares
// against a value the destination no longer has and reports a currency nobody
// established.
func TestATargetStateFailureIsReportedOnAnOtherwiseSuccessfulPush(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target, path := fixtureAt(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)

	refuseWrites(t, path, "no_target_update", "UPDATE", "targets")

	res, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatalf("a target-state failure took the push down with it: %v", err)
	}
	if res.State != "in sync" || len(*delivered) == 0 {
		t.Fatalf("the push did not land, so this is not the case under test: %+v", res)
	}
	if res.StateErr == "" {
		t.Fatal("a push whose target-state write failed reports nothing on the result")
	}
	// And the consequence the field exists to warn about is real: the row still
	// reads as it did before the push.
	reloaded, err := st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded[0].LastPushedAt != "" {
		t.Errorf("the target recorded a push the database refused: %+v", reloaded[0])
	}
	// Which is exactly the state GHState then answers from — against a
	// destination that does hold the blob.
	if got := reloaded[0].GHState(nil, vault.ValueDigest(key, "anything")); got != "never" {
		t.Errorf("a delivered push reads as %q, not as the unrecorded state it is", got)
	}
}
