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
	seedEmptyRenderFor(t, st, "demo", "PROD_ENV_FILE")
}

// seedEmptyRenderFor is seedEmptyRender for a named project, so a test can build
// more than one of them. Each destination must differ: one GitHub secret can be
// claimed by only one target.
func seedEmptyRenderFor(t *testing.T, st *store.Store, project, ghSecret string) {
	t.Helper()
	// A populated project, so this is a target that manages nothing rather than
	// a vault that holds nothing — those are different conditions and only the
	// first is `empty`.
	seedProject(t, st, project, map[string]string{"ALPHA": "a"})
	// Added through the store with a nil key set, which is the state `target
	// add --render-as-secret` leaves when there is no file target to seed from,
	// and the state a target reaches when its last key is dropped.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		tgt, err := m.AddGHRenderTarget(project, "o/r", "home-server", ghSecret, nil)
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

// seedRenderManaging attaches a rendered target that manages the given keys, so
// a test can build a target that DOES belong to a secret's row.
func seedRenderManaging(t *testing.T, st *store.Store, project, ghSecret string, keys []string) {
	t.Helper()
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		tgt, err := m.AddGHRenderTarget(project, "o/r", "home-server", ghSecret, keys)
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
	}{
		{
			name: "empty", state: "empty*", seed: seedEmptyRender,
			says: []string{"manages no keys", "signet target add-key"},
		},
		{
			name: "incomplete", state: "incomplete*", seed: seedIncompleteRender,
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
				{"status", func() error { return runStatus(nil) }},
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
		name string
		seed func(*testing.T, *store.Store)
	}{
		{"empty", seedEmptyRender},
		{"incomplete", seedIncompleteRender},
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
				{"status", func() error { return runStatus(nil) }},
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

// The one part of SGNT-45 that could not be fixed there, and SGNT-46 did.
//
// `status` builds its TARGETS column per secret and attaches a rendered target
// to a row only when `cfg.Manages(sec.Name)`. A target managing no keys manages
// no secret, so it was attached to nothing and left the view entirely — in
// every state, with or without a reason.
//
// `empty` is the state that makes the omission matter: internal/sync/render.go
// calls it the more urgent of the two refusals, because the blob such a target
// would deliver is a complete, well-formed env file containing nothing, which
// the consumer applies in full. The view an operator reaches for when something
// is wrong was the one view that could not report it.
//
// This test replaces the tripwire that pinned the gap, which was written to
// fail when the gap closed and did: the exclusions in the two tests above and
// the README paragraph were updated in the same change.
func TestStatusShowsARenderTargetThatManagesNoSecret(t *testing.T) {
	st := newCLIVault(t)
	seedEmptyRender(t, st)

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})

	// Scoped to the row, not to the output. The note under the table names the
	// destination too, so an unscoped assertion would pass on a target that
	// still had no row — which is the whole subject of this test.
	row := lineWith(t, out, "gh-render:")
	if !strings.Contains(row, "PROD_ENV_FILE") {
		t.Fatalf("the row does not name the destination:\n%s", row)
	}
	if !strings.Contains(row, "empty*") {
		t.Fatalf("the row does not carry the target's state, marked:\n%s", row)
	}
	// The key count stands where a secret name would, because the row is about
	// a target rather than a secret — the notation `target list` already uses.
	if !strings.Contains(row, "(0 keys)") {
		t.Errorf("the row does not say the target manages nothing:\n%s", row)
	}

	// And the mark has its reason under it, worded by the one function all four
	// views share rather than by a copy this row introduced.
	_, refusal := renderState(mustRenderTarget(t, st, "demo"))
	if refusal == nil {
		t.Fatal("the fixture is deliverable, so there is no refusal to word")
	}
	reason := renderConditionReason(refusal)
	if !strings.Contains(out, reason) {
		t.Errorf("the marked row has no reason under it.\nwant: %s\ngot:\n%s", reason, out)
	}

	// The rest of the table is unaffected: this adds a row, it does not replace
	// the project's own.
	if !strings.Contains(out, "ALPHA") {
		t.Errorf("`status` lost the project's secrets:\n%s", out)
	}
}

// The row is emitted at a project boundary in a list ordered by project, which
// is the one piece of new logic a single-project fixture cannot exercise at all.
// Both directions are wrong in their own way:
//
//   - A boundary that fires LATE files a target under the next project's rows.
//   - A boundary that fires EARLY DUPLICATES it: the check runs before every
//     row that could still match, so a target matched by a later secret in the
//     same block gets a subject row saying it belongs to none — and then the
//     later row attaches it anyway. It does not drop the target, because
//     shownRenders is still marked when that row is reached.
//
// So the fixture needs both shapes. Projects with one secret each cannot catch
// the early direction: every row is a boundary there, and firing early is
// indistinguishable from firing correctly — deleting the guard outright leaves
// such a test green.
//
// Four projects: the second has a boundary on both sides, `nnn` holds a target
// matched by the LAST of its two secrets, and the last exercises the end of the
// list rather than a change of project.
func TestStatusFilesEachEmptyRenderTargetUnderItsOwnProject(t *testing.T) {
	st := newCLIVault(t)
	seedEmptyRenderFor(t, st, "aaa", "AAA_ENV_FILE")
	seedProject(t, st, "mmm", map[string]string{"MID": "m"})
	seedProject(t, st, "nnn", map[string]string{"ALPHA": "a", "BETA": "b"})
	seedRenderManaging(t, st, "nnn", "NNN_ENV_FILE", []string{"BETA"})
	seedEmptyRenderFor(t, st, "zzz", "ZZZ_ENV_FILE")

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})

	for _, tc := range []struct{ project, ghSecret string }{
		{"aaa", "AAA_ENV_FILE"},
		{"zzz", "ZZZ_ENV_FILE"},
	} {
		rows := 0
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, tc.ghSecret) && strings.Contains(l, "(0 keys)") {
				rows++
				if !strings.HasPrefix(l, tc.project) {
					t.Errorf("%s's empty target is filed under another project:\n%s", tc.project, l)
				}
			}
		}
		if rows != 1 {
			t.Errorf("%s's empty target got %d rows, want 1:\n%s", tc.project, rows, out)
		}
	}

	// The early direction: nnn's target belongs to BETA's row, which comes
	// after ALPHA's. A boundary that fires before the block ends gives it a
	// subject row claiming it belongs to none — while BETA's row, further down,
	// carries the same destination.
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "NNN_ENV_FILE") && strings.Contains(l, "keys)") {
			t.Errorf("a target matched by a later secret in the same block got a "+
				"subject row saying it belongs to none:\n%s", l)
		}
	}

	// In project order, which is what says the boundary fired in the right
	// place rather than merely firing: aaa's target before mmm's only secret,
	// and mmm's before zzz's target.
	aaa, mmm, zzz := strings.Index(out, "AAA_ENV_FILE"), strings.Index(out, "MID"), strings.Index(out, "ZZZ_ENV_FILE")
	if !(aaa < mmm && mmm < zzz) {
		t.Errorf("the rows are not in project order, so a boundary fired against the wrong block:\n%s", out)
	}

	// Both targets are marked, so both reasons must have been collected — the
	// pairing stateNotes.add exists to hold, across projects.
	if n := strings.Count(out, "  * "); n != 2 {
		t.Errorf("%d notes under the table, want one per marked row (2):\n%s", n, out)
	}
}

// lineWith returns the one output line containing needle, so an assertion about
// a table row cannot be satisfied by the notes printed under the table.
func lineWith(t *testing.T, out, needle string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("no line of the output contains %q:\n%s", needle, out)
	return ""
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
