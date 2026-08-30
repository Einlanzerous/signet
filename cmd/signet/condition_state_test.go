package main

import (
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
)

// seedEmptyRender builds a project whose rendered target manages no keys — the
// `empty` condition, which sync refuses rather than delivering a well-formed
// env file containing nothing.
func seedEmptyRender(t *testing.T, st *store.Store) {
	t.Helper()
	// A populated project, so this is a target that manages nothing rather than
	// a vault that holds nothing — those are different conditions and only the
	// first is `empty`.
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a"})
	// Added through the store with a nil key set, which is the state `target
	// add --render-as-secret` leaves when there is no file target to seed from,
	// and the state a target reaches when its last key is dropped.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		tgt, err := m.AddGHRenderTarget("demo", "o/r", "home-server", "PROD_ENV_FILE", nil)
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "target.render", TargetID: tgt.ID, Details: "fixture",
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// seedIncompleteRender builds a project whose rendered target manages a key the
// vault cannot supply.
//
// The key is attached through the store rather than with `target add-key`,
// which refuses an unresolvable key outright. That guard closes one way into
// this state and not the state itself — a key seeded from a file target, or one
// whose value is removed after it was added, arrives here the same way.
func seedIncompleteRender(t *testing.T, st *store.Store) {
	t.Helper()
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret("demo", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: sec.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	tgt, _ := renderTargetOf(t, st, "demo")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		updated, _, err := m.AddRenderKeys(&tgt, []string{"PENDING"})
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "target.render", TargetID: updated.ID, Details: "fixture",
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeUpdated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The ticket's own complaint. `empty` and `incomplete` are the live state of
// the two refusals `internal/sync/render.go` declines a push for, and they are
// the ONLY refusal kinds still in force when the view is drawn — yet `target
// list` and `status` printed the bare word while the refusals that were already
// over (a resolved shrink guard sitting in `drift`) showed a reason.
func TestTargetListAndStatusSayWhyARenderIsEmptyOrIncomplete(t *testing.T) {
	for _, cond := range []struct {
		name  string
		seed  func(*testing.T, *store.Store)
		state string
		says  []string
		// inStatus is false for `empty`: `status` cannot show such a target at
		// all, for a reason that has nothing to do with reasons — see
		// TestStatusCannotShowARenderTargetThatManagesNoSecret.
		inStatus bool
	}{
		{
			name: "empty", state: "empty*", seed: seedEmptyRender, inStatus: false,
			says: []string{"manages no keys", "signet target add-key"},
		},
		{
			name: "incomplete", state: "incomplete*", seed: seedIncompleteRender, inStatus: true,
			// The offending key is named: an operator told only that something
			// is missing has to run a second command to find out what.
			says: []string{"have no value in the vault", "PENDING", "drop them from the target"},
		},
	} {
		t.Run(cond.name, func(t *testing.T) {
			st := newCLIVault(t)
			cond.seed(t, st)

			views := []struct {
				name string
				run  func() error
			}{
				{"target list", func() error { return runTargetList([]string{"--project", "demo"}) }},
			}
			if cond.inStatus {
				views = append(views, struct {
					name string
					run  func() error
				}{"status", func() error { return runStatus(nil) }})
			}
			for _, view := range views {
				out := captureStdout(t, func() {
					if err := view.run(); err != nil {
						t.Fatal(err)
					}
				})
				if !strings.Contains(out, cond.state) {
					t.Errorf("%s does not mark the %s state as carrying a reason:\n%s",
						view.name, cond.name, out)
				}
				for _, want := range cond.says {
					if !strings.Contains(out, want) {
						t.Errorf("%s does not say %q under a %s target:\n%s",
							view.name, want, cond.name, out)
					}
				}
			}
		})
	}
}

// `status` prints one row per secret, and a rendered target annotates every
// secret it carries. The de-duplication that keeps a 95-key render from
// repeating its refusal 95 times has to cover a derived reason too — it was
// written for a quoted one.
func TestAConditionReasonIsPrintedOncePerDestination(t *testing.T) {
	st := newCLIVault(t)
	seedIncompleteRender(t, st)

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})
	if n := strings.Count(out, "have no value in the vault"); n != 1 {
		t.Errorf("the reason is repeated %d times, once per secret the render carries:\n%s", n, out)
	}
}

// The acceptance criterion that makes this more than three copies of a
// sentence: all four views take their wording from renderConditionReason, so
// they cannot come to describe one refusal two ways.
//
// `render --check` is included because it is where the wording USED to live —
// it had its own `len(cfg.Keys) == 0` test, its own missing-key loop and its
// own text, which is precisely why the other views had nothing to share.
func TestAllFourViewsWordARenderRefusalTheSameWay(t *testing.T) {
	for _, cond := range []struct {
		name     string
		seed     func(*testing.T, *store.Store)
		inStatus bool
	}{
		{"empty", seedEmptyRender, false},
		{"incomplete", seedIncompleteRender, true},
	} {
		t.Run(cond.name, func(t *testing.T) {
			st := newCLIVault(t)
			cond.seed(t, st)

			// The sentence itself, from the one place that produces it.
			_, refusal := renderState(mustRenderTarget(t, st, "demo"))
			if refusal == nil {
				t.Fatal("the fixture is deliverable, so there is no refusal to word")
			}
			reason := renderConditionReason(refusal)

			views := []struct {
				name string
				run  func() error
			}{
				{"target list", func() error { return runTargetList([]string{"--project", "demo"}) }},
				{"render --check", func() error { return runRender([]string{"--project", "demo", "--check"}) }},
				{"render", func() error { return runRender([]string{"--project", "demo"}) }},
			}
			if cond.inStatus {
				views = append(views, struct {
					name string
					run  func() error
				}{"status", func() error { return runStatus(nil) }})
			}
			for _, view := range views {
				out := captureStdout(t, func() {
					// --check exits non-zero on a blocking condition, which
					// both of these are; that is the report, not a failure.
					_ = view.run()
				})
				if !strings.Contains(out, reason) {
					t.Errorf("%s words the %s refusal differently from the shared reason.\nwant: %s\ngot:\n%s",
						view.name, cond.name, reason, out)
				}
			}
		})
	}
}

// mustRenderTarget returns the arguments renderState takes for a project's only
// rendered target, resolved the way the views resolve them.
func mustRenderTarget(t *testing.T, st *store.Store, project string) (*store.Target, store.GHRenderConfig, map[string]string, []byte) {
	t.Helper()
	a, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	want, _, err := a.projectValues(project)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := st.RenderTargetsForProject(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("project %s has %d rendered targets, want 1", project, len(targets))
	}
	cfg, err := targets[0].GHRenderConfig()
	if err != nil {
		t.Fatal(err)
	}
	return &targets[0], cfg, want, a.key
}

// A deliverable target carries no derived reason, so it is not marked and
// collects no note. The other half of every mark: one that appears when nothing
// is wrong is one operators learn to skip, including on the run where it means
// something (SGNT-31).
func TestADeliverableRenderCarriesNoConditionReason(t *testing.T) {
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

	state, refusal := renderState(mustRenderTarget(t, st, "demo"))
	if refusal != nil {
		t.Fatalf("a complete render was refused: %v", refusal)
	}
	if state.reason != "" {
		t.Errorf("a deliverable render carries a condition reason: %q", state.reason)
	}
	if got := markState(&store.Target{}, state); strings.HasSuffix(got, "*") {
		t.Errorf("a deliverable render was marked: %q", got)
	}

	for _, view := range []struct {
		name string
		run  func() error
	}{
		{"target list", func() error { return runTargetList([]string{"--project", "demo"}) }},
		{"status", func() error { return runStatus(nil) }},
		{"render --check", func() error { return runRender([]string{"--project", "demo", "--check"}) }},
	} {
		out := captureStdout(t, func() {
			if err := view.run(); err != nil {
				t.Fatal(err)
			}
		})
		if strings.Contains(out, "*") {
			t.Errorf("%s marked a target with nothing to explain:\n%s", view.name, out)
		}
		if strings.Contains(out, "sync will refuse") {
			t.Errorf("%s predicted a refusal that will not happen:\n%s", view.name, out)
		}
	}
}

// stateReasonFor is the join, and the property worth pinning is that neither
// source is lost when the other is absent — the mark and the note read this one
// value, so a source it forgets is a row marked with nothing under it.
func TestBothSourcesOfAReasonReachTheMarkAndTheNote(t *testing.T) {
	refused := &store.Target{LastState: store.TargetRefused, LastError: "boom"}
	clean := &store.Target{}

	// Quoted: from the target's push history, gated on the state.
	if got := stateReasonFor(refused, answered("drift")); !strings.Contains(got, "boom") {
		t.Errorf("a quoted reason did not survive the join: %q", got)
	}
	// Derived: from the vault as it stands, carried on the state itself and
	// needing no history at all.
	derived := answered("incomplete").because("BETA has no value")
	if got := stateReasonFor(clean, derived); got != "BETA has no value" {
		t.Errorf("a derived reason did not survive the join: %q", got)
	}
	// And a derived reason survives a call site's word substitution, which is
	// the whole reason it rides on shownState rather than beside it.
	if got := stateReasonFor(clean, derived.substituting("unresolved")); got != "BETA has no value" {
		t.Errorf("a substitution dropped the derived reason: %q", got)
	}
	if got := stateReasonFor(clean, answered("in sync")); got != "" {
		t.Errorf("a target with neither source produced a reason: %q", got)
	}
	// The mark and the note agree, for both sources — this is the invariant
	// stateReasonFor exists to hold.
	for _, tc := range []struct {
		name   string
		target *store.Target
		state  shownState
	}{
		{"quoted", refused, answered("drift")},
		{"derived", clean, derived},
		{"neither", clean, answered("in sync")},
	} {
		var n stateNotes
		n.add(tc.target, "o/r · TOKEN", tc.state)
		marked := strings.HasSuffix(markState(tc.target, tc.state), "*")
		if marked != (len(n.lines) == 1) {
			t.Errorf("%s: marked=%v but collected %d notes", tc.name, marked, len(n.lines))
		}
	}
}

// The one part of SGNT-45 that is NOT fixed, pinned so it is discovered rather
// than rediscovered.
//
// `status` builds its TARGETS column per secret, and attaches a rendered target
// to a row only when `cfg.Manages(sec.Name)`. A target that manages no keys
// manages no secret, so it is attached to nothing — `status` does not show it
// in any state, with or without a reason. That is why the `empty` half of this
// ticket's acceptance ("`target list` and `status` show why") is met by `target
// list`, `render --check` and `render` and not by `status`.
//
// It is pre-existing and structural, not a consequence of the change around it:
// giving `status` somewhere to print a target that belongs to no secret's row
// is a change to that table's shape, which is a different ticket from wording a
// reason. Tracked as SGNT-46.
//
// If a future change gives `status` a home for such a target, this test should
// FAIL — at which point the exclusions in the two tests above, the note in
// stateHidesItsReason and the README paragraph all want updating together.
func TestStatusCannotShowARenderTargetThatManagesNoSecret(t *testing.T) {
	st := newCLIVault(t)
	seedEmptyRender(t, st)

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "PROD_ENV_FILE") {
		t.Fatalf("`status` now shows a target that manages no keys — good, but the "+
			"exclusions written around this gap are now wrong; see this test's doc:\n%s", out)
	}
	// The rest of the table is unaffected: the project's other targets still
	// report, so this is one target missing rather than a broken view.
	if !strings.Contains(out, "ALPHA") {
		t.Errorf("`status` lost the project's secrets, not just the empty target:\n%s", out)
	}
}

// seedBrokenDerivation gives the project a managed key whose secret exists and
// cannot be resolved — a derivation naming an input that is not there.
//
// Built through the store rather than with `runDerive`, which validates inputs
// up front (TestDeriveRejectsAnUnresolvableTemplate). That guard closes the way
// IN to this state; it does not close the state, which is reached whenever an
// input is removed after the derivation was written.
//
// This is the shape no fixture in this package had, and it is the only one that
// puts a key in `problems` — resolveInto skips resolve.ErrNoVersion, so a
// secret that is merely unset lands in neither `want` nor `problems`.
func seedBrokenDerivation(t *testing.T, st *store.Store) {
	t.Helper()
	seedProject(t, st, "demo", map[string]string{"ALPHA": "a"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret("demo", "DSN", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		if err := m.SetDerivation(sec.ID, "postgres://u:{{demo/GONE}}@h/db"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: sec.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	tgt, _ := renderTargetOf(t, st, "demo")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		updated, _, err := m.AddRenderKeys(&tgt, []string{"DSN"})
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "target.render", TargetID: updated.ID, Details: "fixture",
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeUpdated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The one thing `render --check` still adds over the shared sentence, and the
// sole justification for the hint that points at it (found by the reviewer on
// #47).
//
// The shared reason names WHICH keys have no value. Only this view can say WHY
// a particular one does not, and after this change it prints a detail line only
// for a key with an actual explanation — so a fixture whose key is merely unset
// exercises none of it. Nothing in this package had the other shape, which meant
// the block could have been deleted with the suite still green.
func TestRenderCheckSaysWhyAKeyCannotBeResolved(t *testing.T) {
	st := newCLIVault(t)
	seedBrokenDerivation(t, st)

	out := captureStdout(t, func() {
		// Blocking, so this returns errRenderCheckBlocked. That is the report,
		// not a failure to run.
		_ = runRender([]string{"--project", "demo", "--check"})
	})

	// Scoped to the target's own report. `render --check` prints a project-wide
	// "cannot be resolved" section first, which names the same input — an
	// unscoped Contains passes on that alone and pins nothing here, which is
	// the vacuous shape the reviewer found in the neighbouring
	// TestRenderCheckReportsUnresolvableSecretsAsSuchNotAsDrift.
	const headline = "INCOMPLETE — "
	i := strings.Index(out, headline)
	if i < 0 {
		t.Fatalf("`render --check` does not report the target as incomplete:\n%s", out)
	}
	report := out[i:]

	// The shared sentence still leads, naming the key.
	if !strings.Contains(report, "DSN") {
		t.Fatalf("the reason does not name the unresolvable key:\n%s", report)
	}
	// And the part only this view carries: what is actually wrong with it.
	if !strings.Contains(report, "GONE") {
		t.Errorf("the target's report does not name the missing input, so `render --check` "+
			"adds nothing over the one-line reason the other three views print:\n%s", report)
	}
}

// The other side of the same block, and the reason the hint had to be
// qualified: a key that is simply unset has no explanation to give, so no
// detail line is printed for it. A bare "no value set" beside a name the line
// above already printed is noise, and burying a real explanation among many of
// them is how the detail stops being read.
func TestRenderCheckAddsNoDetailLineForAKeyThatIsMerelyUnset(t *testing.T) {
	st := newCLIVault(t)
	seedIncompleteRender(t, st)

	out := captureStdout(t, func() {
		_ = runRender([]string{"--project", "demo", "--check"})
	})

	if !strings.Contains(out, "PENDING") {
		t.Fatalf("the key is not named at all:\n%s", out)
	}
	if strings.Contains(out, "no value set") {
		t.Errorf("an unset key got a detail line saying only what the reason already said:\n%s", out)
	}
}
