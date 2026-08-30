package main

import (
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
)

// deliverRecordingNothing puts the project's rendered target into the state
// `unknown` answers for: last_pushed_at set, and neither fingerprint column
// written, so there is nothing to compare the next render against.
//
// prov == nil is that update — UpdateTargetPush's nil branch writes the
// timestamp and leaves the fingerprint columns alone — which is also why a
// refusal layered on top keeps them empty.
//
// NO RELEASE WRITES THIS ROW; see GHState's doc for the enumeration of writers.
// These tests pin what the four views show if a future push path ever leaves
// both columns unwritten, which is why the branch is kept. They are guards, not
// regression tests for an observed failure.
//
// It returns the target ID rather than the Target, because the row it read is
// the one BEFORE the write — a struct handed back from here would still carry
// LastPushedAt == "" and answer `never`, which is the shape this whole file
// argues against (see the sibling store test's `reload`). An id cannot be
// mistaken for state.
func deliverRecordingNothing(t *testing.T, st *store.Store, project string) string {
	t.Helper()
	targets, err := st.RenderTargetsForProject(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("project %s has %d rendered targets, want 1", project, len(targets))
	}
	if err := st.UpdateTargetPush(targets[0].ID, "in sync", "", nil, "2026-08-20T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	return targets[0].ID
}

// seedUnknownRender builds a project whose rendered target recorded nothing to
// compare and has since been refused — the one combination that reaches
// `unknown` carrying a reason.
func seedUnknownRender(t *testing.T, st *store.Store) {
	t.Helper()
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a", "BETA": "b"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	id := deliverRecordingNothing(t, st, "demo")
	if err := st.UpdateTargetPush(id, store.TargetRefused, theShrinkRefusal, nil, ""); err != nil {
		t.Fatal(err)
	}
}

// The state reaching the views at all. Until SGNT-43 every one of these would
// have printed `drift` — "now stale", with a sync suggested — about a
// destination whose currency signet had no record of either way.
func TestADeliveryWithNothingRecordedIsReportedAsUnknown(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a", "BETA": "b"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	deliverRecordingNothing(t, st, "demo")

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"target list", func() error { return runTargetList([]string{"--project", "demo"}) }},
		{"status", func() error { return runStatus(nil) }},
		{"render --check", func() error { return runRender([]string{"--project", "demo", "--check"}) }},
	} {
		out := captureStdout(t, func() {
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "unknown") {
			t.Errorf("%s does not report the state as unknown:\n%s", tc.name, out)
		}
		if strings.Contains(out, "drift") {
			t.Errorf("%s claims the destination is stale, having nothing to compare:\n%s", tc.name, out)
		}
		// Nothing was refused here, so nothing is marked. The state word is the
		// whole fact, and a `*` with no reason under it is the false alarm the
		// mark exists to avoid.
		if strings.Contains(out, "unknown*") {
			t.Errorf("%s marked a state carrying no reason:\n%s", tc.name, out)
		}
	}
}

// The write path's trailing note, which words the same state as prose.
func TestTheRenderNoteReportsUnrecordedCurrencyRatherThanStaleness(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a", "BETA": "b"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	deliverRecordingNothing(t, st, "demo")

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "demo"}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "with nothing recorded to compare; currency unknown") {
		t.Errorf("the note does not report currency as unrecorded:\n%s", out)
	}
	if strings.Contains(out, "now stale") {
		t.Errorf("the note claims the destination is stale, having nothing to compare:\n%s", out)
	}
	// Still counted as undelivered: a sync is what writes the fingerprint that
	// ends this state, so the suggestion is earned.
	if !strings.Contains(out, "run `signet sync`") {
		t.Errorf("the note does not suggest the sync that would settle it:\n%s", out)
	}
}

// The combination SGNT-43's CLI half turns on, and the reason `unknown`'s
// exclusion from the reason mark had to be re-decided rather than inherited.
//
// A refusal leaves the fingerprint columns alone, so a target that recorded
// nothing and is then refused lands in `unknown` — with a refusal that is
// still in force. The state word says only that signet cannot tell whether
// the destination is current; everything actionable is in the reason.
func TestAllFourViewsSayWhyAnUnknownTargetWasRefused(t *testing.T) {
	st := newCLIVault(t)
	seedUnknownRender(t, st)

	for _, tc := range []struct {
		name   string
		run    func() error
		marked bool // false for the prose view, which has no state word to mark
	}{
		{"target list", func() error { return runTargetList([]string{"--project", "demo"}) }, true},
		{"status", func() error { return runStatus(nil) }, true},
		{"render --check", func() error { return runRender([]string{"--project", "demo", "--check"}) }, true},
		{"render", func() error { return runRender([]string{"--project", "demo"}) }, false},
	} {
		out := captureStdout(t, func() {
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "the last push attempt was declined:") {
			t.Errorf("%s shows an unknown state without the refusal that is still in force:\n%s", tc.name, out)
		}
		if !strings.Contains(out, "--allow-shrink") {
			t.Errorf("%s does not carry the refusal's own text, which names the fix:\n%s", tc.name, out)
		}
		if tc.marked && !strings.Contains(out, "unknown*") {
			t.Errorf("%s did not mark the state as carrying a reason:\n%s", tc.name, out)
		}
		if !tc.marked && strings.Contains(out, "unknown*") {
			t.Errorf("%s is prose and has no state word, but grew a marker:\n%s", tc.name, out)
		}
	}
}

// The boundary of the reorder, and the case that keeps it from being applied
// too widely (found by the reviewer on #46).
//
// A STORED secret's push records no digest — resolve.Current leaves
// Resolved.Digest empty for one, and PushSecret writes that straight into the
// provenance — so any gh-actions target of a stored secret carries an empty
// fingerprint. Convert that secret with `derive --replace` and every view
// starts supplying a digest to compare against a column the stored pushes never
// wrote, which lands in the same branch as a row that recorded neither.
//
// It is NOT the same fact. The version id says so: it is written only for a
// stored secret's push, so a non-empty one on a secret that now resolves to a
// digest means the destination holds a value the vault has replaced. Reporting
// `unknown` there would be weaker than the row's own evidence — signet saying
// it cannot tell about a difference it can prove.
func TestAStoredSecretConvertedToDerivedStillReportsDrift(t *testing.T) {
	st := newCLIVault(t)
	setValue(t, "p", "PW", "hunter2")
	setValue(t, "p", "DSN", "hand-written")
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--secret", "p/DSN", "--gh-repo", "o/r", "--gh-secret", "DSN", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})

	// The row a stored secret's successful push leaves: a version id, and the
	// empty digest PushSecret writes for a secret that has no derived value to
	// fingerprint.
	sec := mustSecret(t, st, "p", "DSN")
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := st.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateTargetPush(targets[0].ID, "in sync", "",
		&store.PushProvenance{VersionID: cur.ID}, "2026-08-20T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	// The conversion. From here the secret is derived, so every view asks
	// GHState with a digest.
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--replace",
		"--from", "u:{{PW}}@h"}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runTargetList([]string{"--project", "p"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "unknown") {
		t.Errorf("signet reports it cannot tell about a difference the row proves — the "+
			"destination holds a stored value the conversion replaced:\n%s", out)
	}
	if !strings.Contains(out, "drift") {
		t.Errorf("`target list` does not report the superseded destination as drifted:\n%s", out)
	}
}
