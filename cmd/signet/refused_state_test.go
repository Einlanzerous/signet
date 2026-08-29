package main

import (
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
)

// theShrinkRefusal is the reason a real shrink guard writes. Used verbatim
// because its length is the point: it is why the reason cannot become a table
// column, and why these views mark the row and print it underneath instead.
const theShrinkRefusal = "this render drops 1 key(s) the last push delivered: BETA — " +
	"they would become empty in the deployed environment; re-add them, or " +
	"pass --allow-shrink if the removal is deliberate"

// refuseTheRenderTarget puts the project's rendered target into the state a
// declined push leaves: last_state `refused`, the reason in last_error, and a
// previous successful delivery still on record.
func refuseTheRenderTarget(t *testing.T, st *store.Store, project string) {
	t.Helper()
	targets, err := st.RenderTargetsForProject(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("project %s has %d rendered targets, want 1", project, len(targets))
	}
	if err := st.UpdateTargetPush(targets[0].ID, store.TargetRefused, theShrinkRefusal,
		&store.PushProvenance{Digest: "anolderblob", Keys: []string{"ALPHA", "BETA"}},
		"2026-08-20T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

// seedRefusedRender builds a project with a rendered target whose last push was
// declined.
func seedRefusedRender(t *testing.T, st *store.Store) {
	t.Helper()
	path := seedProject(t, st, "demo", map[string]string{"ALPHA": "a", "BETA": "b"})
	captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "demo", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	_ = path
	refuseTheRenderTarget(t, st, "demo")
}

// A refused push reads as ordinary drift in `target list` — true about
// currency, silent about the decision that caused it. The reason was reachable
// only from `signet audit`, which requires already suspecting a refusal
// happened (SGNT-35).
func TestTargetListSaysWhyARefusedTargetIsStale(t *testing.T) {
	st := newCLIVault(t)
	seedRefusedRender(t, st)

	out := captureStdout(t, func() {
		if err := runTargetList([]string{"--project", "demo"}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "drift*") {
		t.Errorf("a refused target's state is not marked as carrying a reason:\n%s", out)
	}
	if !strings.Contains(out, "push declined") {
		t.Errorf("`target list` does not say the push was declined:\n%s", out)
	}
	if !strings.Contains(out, "--allow-shrink") {
		t.Errorf("the refusal's own reason — which names the fix — is not shown:\n%s", out)
	}
	// The table keeps its five columns: the reason is a note under it, not a
	// sixth column that would widen every row to the worst refusal. The note
	// itself is the line starting "  * "; any *other* line carrying the reason
	// means it leaked into the table.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  * ") {
			continue
		}
		if strings.Contains(line, "--allow-shrink") {
			t.Errorf("the reason was put in the table row rather than under it:\n%s", line)
		}
	}
	// And the note comes after the row it annotates, or it is not annotating it.
	if strings.Index(out, "  * ") < strings.Index(out, "drift*") {
		t.Errorf("the note is printed above the table it annotates:\n%s", out)
	}
}

// `status` shows the same target in its TARGETS column, and had the same gap.
func TestStatusSaysWhyARefusedTargetIsStale(t *testing.T) {
	st := newCLIVault(t)
	seedRefusedRender(t, st)

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "drift*") {
		t.Errorf("`status` does not mark the refused target's state:\n%s", out)
	}
	if !strings.Contains(out, "push declined") {
		t.Errorf("`status` does not say the push was declined:\n%s", out)
	}
	// One note, not one per secret the render carries. A 95-key render would
	// otherwise repeat its refusal 95 times and bury the table it annotates.
	if n := strings.Count(out, "push declined"); n != 1 {
		t.Errorf("the refusal is repeated %d times, once per secret the render carries", n)
	}
}

// `render --check` is the view a deploy script reads, and it too showed the
// bare state word.
func TestRenderCheckSaysWhyARefusedTargetIsStale(t *testing.T) {
	st := newCLIVault(t)
	seedRefusedRender(t, st)

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "demo", "--check"}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "drift*") {
		t.Errorf("`render --check` does not mark the refused target's state:\n%s", out)
	}
	if !strings.Contains(out, "push declined") {
		t.Errorf("`render --check` does not say the push was declined:\n%s", out)
	}
}

// The other half of the same bug, and the one SGNT-31 was about: a marker that
// appears when nothing is wrong is one operators learn to skip, including on
// the run where it means something. A healthy target carries no mark and no
// note.
func TestAHealthyTargetIsNotMarked(t *testing.T) {
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
		if strings.Contains(out, "*") {
			t.Errorf("%s marked a target that has no reason to show:\n%s", tc.name, out)
		}
		if strings.Contains(out, "push declined") || strings.Contains(out, "last push failed") {
			t.Errorf("%s reported a refusal that did not happen:\n%s", tc.name, out)
		}
	}
}

// An errored target — a delivery attempted and failed — is a different fact
// from a refusal, and the wording has to keep them apart: "declined" means the
// destination still holds what the last good push left, "failed" does not.
func TestARefusalAndAFailureAreWordedDifferently(t *testing.T) {
	refused := &store.Target{LastState: store.TargetRefused, LastError: "boom"}
	failed := &store.Target{LastState: "error", LastError: "boom"}

	if got := stateReason(refused); !strings.HasPrefix(got, "push declined") {
		t.Errorf("a refusal reads as %q", got)
	}
	if got := stateReason(failed); !strings.HasPrefix(got, "last push failed") {
		t.Errorf("a failure reads as %q", got)
	}
	if markState(&store.Target{}, "drift") != "drift" {
		t.Error("a target with no reason was marked anyway")
	}
	if markState(refused, "drift") != "drift*" {
		t.Error("a target carrying a reason was not marked")
	}
}
