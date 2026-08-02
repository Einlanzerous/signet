package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Einlanzerous/signet/internal/config"
	"github.com/Einlanzerous/signet/internal/store"
)

// newCLIVault points the CLI's configuration at a throwaway vault and
// initializes it, so subcommands can be driven exactly as main dispatches them.
func newCLIVault(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SIGNET_DB", filepath.Join(dir, "signet.db"))
	t.Setenv("SIGNET_MASTER_KEY_FILE", filepath.Join(dir, "master.key"))
	if err := runInit(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(config.Load().DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func expiryOf(t *testing.T, st *store.Store, project, name string) string {
	t.Helper()
	sec, err := st.GetSecret(project, name)
	if err != nil {
		t.Fatal(err)
	}
	if sec == nil {
		t.Fatalf("no secret %s/%s", project, name)
	}
	return sec.ExpiresAt
}

func day(t *testing.T, date string) string {
	t.Helper()
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		t.Fatal(err)
	}
	return d.UTC().Format(time.RFC3339)
}

// --expires on an existing secret used to be parsed and then dropped: the value
// rotated and the old date stayed. Rotating a credential is precisely when both
// move together, so this is the path the expired-PAT error tells an operator to
// take.
func TestSetMovesExpiryOnExistingSecret(t *testing.T) {
	st := newCLIVault(t)
	if err := runSet([]string{"--project", "signet", "--name", "SIGNET_PAT", "--generate", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "signet", "SIGNET_PAT"), day(t, "2026-10-19"); got != want {
		t.Fatalf("create: expiry %q want %q", got, want)
	}

	if err := runSet([]string{"--project", "signet", "--name", "SIGNET_PAT", "--generate", "--expires", "2027-01-15"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "signet", "SIGNET_PAT"), day(t, "2027-01-15"); got != want {
		t.Fatalf("update: expiry %q want %q", got, want)
	}

	// The ledger has to name the second change; a version write alone does not
	// say the expiry moved.
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want the newest entry, got %d", len(entries))
	}
	if want := "expiry set to 2027-01-15"; !strings.Contains(entries[0].Details, want) {
		t.Fatalf("ledger entry %q does not record %q", entries[0].Details, want)
	}
}

// An absent flag means "leave the expiry alone" — a plain rotation must not
// silently clear the date it was set with.
func TestSetWithoutExpiryFlagKeepsExpiry(t *testing.T) {
	st := newCLIVault(t)
	if err := runSet([]string{"--project", "p", "--name", "N", "--generate", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if err := runSet([]string{"--project", "p", "--name", "N", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "p", "N"), day(t, "2026-10-19"); got != want {
		t.Fatalf("expiry %q want %q — a rotation dropped it", got, want)
	}
}

// An explicit empty --expires clears it, matching the API's set-expiry.
func TestSetExplicitEmptyExpiryClears(t *testing.T) {
	st := newCLIVault(t)
	if err := runSet([]string{"--project", "p", "--name", "N", "--generate", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if err := runSet([]string{"--project", "p", "--name", "N", "--generate", "--expires", ""}); err != nil {
		t.Fatal(err)
	}
	if got := expiryOf(t, st, "p", "N"); got != "" {
		t.Fatalf("expiry %q want cleared", got)
	}
}
