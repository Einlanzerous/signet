package main

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/ops"
	"github.com/Einlanzerous/signet/internal/store"
)

// seedExpireSecret stores a secret whose value is a known marker, so a test can
// prove the verb never surfaces it.
const expireMarker = "hunter2-MARKER-value-0123456789"

func seedExpireSecret(t *testing.T) *store.Store {
	t.Helper()
	st := newCLIVault(t)
	if err := storeValue("p", "N", "", expireMarker, store.Issued, "", false, false); err != nil {
		t.Fatal(err)
	}
	return st
}

func expiryRecords(t *testing.T, st *store.Store, project, name string) []store.AuditEntry {
	t.Helper()
	sec, err := st.GetSecret(project, name)
	if err != nil || sec == nil {
		t.Fatalf("secret %s/%s: %v", project, name, err)
	}
	all, err := st.ListAudit(1000, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == ops.ActionSetExpiry {
			out = append(out, e)
		}
	}
	return out
}

func TestExpireSetsTheDateShowsInStatusAndWritesOneRecord(t *testing.T) {
	st := seedExpireSecret(t)
	if err := runExpire([]string{"--secret", "p/N", "--on", "2999-02-24"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "p", "N"), day(t, "2999-02-24"); got != want {
		t.Fatalf("expiry %q want %q", got, want)
	}
	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "2999-02-24") {
		t.Fatalf("status does not show the expiry:\n%s", out)
	}
	recs := expiryRecords(t, st, "p", "N")
	if len(recs) != 1 {
		t.Fatalf("want exactly one secret.set-expiry record, got %d", len(recs))
	}
	if recs[0].Status == nil || recs[0].Status.Outcome != store.OutcomeUpdated {
		t.Fatalf("outcome %+v want updated", recs[0].Status)
	}
	if recs[0].EventKind != store.KindPolicyChange {
		t.Fatalf("kind %q want policy change", recs[0].EventKind)
	}
}

func TestExpireWithTheSameDateAgainIsUnchanged(t *testing.T) {
	st := seedExpireSecret(t)
	for i := 0; i < 2; i++ {
		if err := runExpire([]string{"--secret", "p/N", "--on", "2999-02-24"}); err != nil {
			t.Fatal(err)
		}
	}
	recs := expiryRecords(t, st, "p", "N") // newest first
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if got := recs[0].Status.Outcome; got != store.OutcomeUnchanged {
		t.Fatalf("repeat outcome %q want unchanged", got)
	}
	if got := recs[1].Status.Outcome; got != store.OutcomeUpdated {
		t.Fatalf("first outcome %q want updated", got)
	}
}

func TestExpireClearRemovesTheExpiry(t *testing.T) {
	st := seedExpireSecret(t)
	if err := runExpire([]string{"--secret", "p/N", "--on", "2999-02-24"}); err != nil {
		t.Fatal(err)
	}
	if err := runExpire([]string{"--secret", "p/N", "--clear"}); err != nil {
		t.Fatal(err)
	}
	if got := expiryOf(t, st, "p", "N"); got != "" {
		t.Fatalf("expiry %q want cleared", got)
	}
	if recs := expiryRecords(t, st, "p", "N"); recs[0].Status.Outcome != store.OutcomeUpdated {
		t.Fatalf("clear outcome %q want updated", recs[0].Status.Outcome)
	}
	// Clearing what is already clear is the no-op case.
	if err := runExpire([]string{"--secret", "p/N", "--clear"}); err != nil {
		t.Fatal(err)
	}
	if recs := expiryRecords(t, st, "p", "N"); recs[0].Status.Outcome != store.OutcomeUnchanged {
		t.Fatalf("second clear outcome %q want unchanged", recs[0].Status.Outcome)
	}
}

func TestExpireRefusalsExitNonZeroAndChangeNothing(t *testing.T) {
	st := seedExpireSecret(t)
	if err := runExpire([]string{"--secret", "p/N", "--on", "2999-02-24"}); err != nil {
		t.Fatal(err)
	}
	before, err := st.ListAudit(1000, "")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"unknown secret":       {"--secret", "p/NOPE", "--on", "2999-03-01"},
		"unknown project":      {"--secret", "nope/N", "--clear"},
		"malformed date":       {"--secret", "p/N", "--on", "24-02-2999"},
		"not a date":           {"--secret", "p/N", "--on", "soon"},
		"on with clear":        {"--secret", "p/N", "--on", "2999-03-01", "--clear"},
		"empty on":             {"--secret", "p/N", "--on", ""},
		"neither on nor clear": {"--secret", "p/N"},
		"no secret":            {"--on", "2999-03-01"},
		"malformed ref":        {"--secret", "pN", "--on", "2999-03-01"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := runExpire(args); err == nil {
				t.Fatalf("runExpire(%v) succeeded, want an error", args)
			}
		})
	}
	if got, want := expiryOf(t, st, "p", "N"), day(t, "2999-02-24"); got != want {
		t.Fatalf("a refused call changed the expiry to %q", got)
	}
	after, _ := st.ListAudit(1000, "")
	if len(after) != len(before) {
		t.Fatalf("refused calls wrote %d ledger entries", len(after)-len(before))
	}
}

func TestExpireNeverReadsOrPrintsTheValue(t *testing.T) {
	st := seedExpireSecret(t)
	// A closed stdin would fail a verb that tried to read a value from it.
	orig := os.Stdin
	os.Stdin = nil
	t.Cleanup(func() { os.Stdin = orig })

	before, _ := st.CurrentVersion(mustSecretID(t, st))
	out := captureStdout(t, func() {
		for _, a := range [][]string{
			{"--secret", "p/N", "--on", "2999-02-24"},
			{"--secret", "p/N", "--on", "2999-02-24"},
			{"--secret", "p/N", "--clear"},
		} {
			if err := runExpire(a); err != nil {
				t.Fatal(err)
			}
		}
	})
	for _, frag := range []string{expireMarker, expireMarker[:8], expireMarker[len(expireMarker)-8:]} {
		if strings.Contains(out, frag) {
			t.Fatalf("output contains part of the value %q:\n%s", frag, out)
		}
	}
	after, _ := st.CurrentVersion(mustSecretID(t, st))
	if before.VersionNo != after.VersionNo || before.VHash != after.VHash {
		t.Fatalf("the value changed: v%d #%s -> v%d #%s", before.VersionNo, before.VHash, after.VersionNo, after.VHash)
	}
	for _, e := range expiryRecords(t, st, "p", "N") {
		if strings.Contains(e.Details, expireMarker) {
			t.Fatalf("ledger details carry the value: %q", e.Details)
		}
	}
}

func mustSecretID(t *testing.T, st *store.Store) string {
	t.Helper()
	sec, err := st.GetSecret("p", "N")
	if err != nil || sec == nil {
		t.Fatal("no secret p/N", err)
	}
	return sec.ID
}

// set, rotate and expire must agree on what a date is.
func TestExpireAndExpiresFlagAgreeOnDates(t *testing.T) {
	for _, d := range []string{"2027-02-24", "2027-2-24", "2027-02-30", "2027-02-24T00:00:00Z", " 2027-02-24", "nope"} {
		want, _, wantErr := parseExpiry(flagSetWith("expires", d), d)
		got, gotErr := ops.ParseExpiry(d)
		if (wantErr == nil) != (gotErr == nil) || (wantErr == nil && want != got) {
			t.Errorf("%q: parseExpiry (%q, %v) vs ops.ParseExpiry (%q, %v)", d, want, wantErr, got, gotErr)
		}
	}
}

func flagSetWith(name, val string) *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String(name, "", "")
	_ = fs.Parse([]string{"--" + name, val})
	return fs
}
