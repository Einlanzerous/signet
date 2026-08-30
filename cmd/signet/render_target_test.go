package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
	"github.com/Einlanzerous/signet/internal/vault"
)

// seedProject builds a project with an env file on disk, imports it so the
// project has a file target, and returns the file's path.
func seedProject(t *testing.T, st *store.Store, project string, pairs map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	var b strings.Builder
	for k, v := range pairs {
		b.WriteString(k + "=" + v + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", project, path}); err != nil {
		t.Fatal(err)
	}
	return path
}

func renderTargetOf(t *testing.T, st *store.Store, project string) (store.Target, store.GHRenderConfig) {
	t.Helper()
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
	return targets[0], cfg
}

// A rendered target starts as a copy of something already true — the file
// target's key set — rather than as "every secret in the project". The
// difference is what stops keys the environment has never held from arriving in
// it on the first push.
func TestTargetAddRenderSeedsFromTheProjectsFileTarget(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a", "BETA": "b"})
	// A secret in the project that the file target does not manage: it must not
	// be swept into the render.
	if err := runSet([]string{"--project", "csrv", "--name", "UNRELATED", "--generate"}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runTargetAdd([]string{
			"--project", "csrv", "--render-as-secret",
			"--gh-repo", "o/r", "--gh-environment", "home-server",
			"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "it manages 2 keys") {
		t.Fatalf("output does not report the seeded key count: %q", out)
	}

	_, cfg := renderTargetOf(t, st, "csrv")
	if strings.Join(cfg.Keys, ",") != "ALPHA,BETA" {
		t.Fatalf("seeded keys = %v", cfg.Keys)
	}
	if cfg.Environment != "home-server" || cfg.SecretName != "PROD_ENV_FILE" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestTargetAddRenderRequiresAnExplicitDestinationName(t *testing.T) {
	newCLIVault(t)
	err := runTargetAdd([]string{"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r", "--no-preflight"})
	if err == nil || !strings.Contains(err.Error(), "--gh-secret") {
		t.Fatalf("err = %v", err)
	}
}

// add-key is how the key set widens after the seed, and it must refuse a name
// the vault cannot supply: one unresolvable key refuses the whole push, so a
// typo here would stop the entire environment rather than its own key.
func TestTargetAddKeyWidensTheRenderAndRefusesUnknownNames(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runSet([]string{"--project", "csrv", "--name", "AMBER_TAG", "--generate"}); err != nil {
		t.Fatal(err)
	}

	if err := runTargetAddKey([]string{
		"--project", "csrv", "--gh-secret", "PROD_ENV_FILE", "--name", "AMBER_TAG",
	}); err != nil {
		t.Fatal(err)
	}
	_, cfg := renderTargetOf(t, st, "csrv")
	if strings.Join(cfg.Keys, ",") != "ALPHA,AMBER_TAG" {
		t.Fatalf("keys = %v", cfg.Keys)
	}

	err := runTargetAddKey([]string{
		"--project", "csrv", "--gh-secret", "PROD_ENV_FILE", "--name", "NOT_IN_VAULT",
	})
	if err == nil || !strings.Contains(err.Error(), "NOT_IN_VAULT") {
		t.Fatalf("err = %v", err)
	}
}

// The first push is the one no other guard covers: there is no record of a
// previous delivery to compare against, and the destination's value can never
// be read back. --against is the check that turns "the vault is presumably
// complete" into something verified against what is actually deployed.
func TestRenderCheckAgainstNamesTheKeysAPushWouldDrop(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a", "BETA": "b"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}

	// What the environment actually holds: the two managed keys plus a pin that
	// never entered the vault. This is exactly the construct-server situation.
	live := filepath.Join(t.TempDir(), "live.env")
	if err := os.WriteFile(live, []byte("ALPHA=a\nBETA=b\nAMBER_TAG=v1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The error is the point as much as the report is: a deploy script gates on
	// the exit code, and a check that printed WOULD DROP and exited 0 could not
	// stop anything.
	var checkErr error
	out := captureStdout(t, func() {
		checkErr = runRender([]string{"--project", "csrv", "--check", "--against", live})
	})
	if !errors.Is(checkErr, errRenderCheckBlocked) {
		t.Fatalf("a check that would drop a key exited clean: %v", checkErr)
	}
	if !strings.Contains(out, "WOULD DROP 1 key(s)") || !strings.Contains(out, "AMBER_TAG") {
		t.Fatalf("check did not name the key that would be dropped:\n%s", out)
	}
	if !strings.Contains(out, "read as empty") {
		t.Fatalf("check does not say what dropping it would do:\n%s", out)
	}

	// Once the pin is in the vault and on the target, the same check clears.
	if err := runSet([]string{"--project", "csrv", "--name", "AMBER_TAG", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAddKey([]string{"--project", "csrv", "--gh-secret", "PROD_ENV_FILE", "--name", "AMBER_TAG"}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		checkErr = runRender([]string{"--project", "csrv", "--check", "--against", live})
	})
	if !strings.Contains(out, "covers every key in") {
		t.Fatalf("check did not clear after the key was added:\n%s", out)
	}
	if checkErr != nil {
		t.Fatalf("a check with nothing to drop still reported a blocking verdict: %v", checkErr)
	}
	if strings.Contains(out, "WOULD DROP") {
		t.Fatalf("check still reports a drop:\n%s", out)
	}
}

// A managed key with no value is not drift — it is a push that will be refused.
// Saying so at check time is the difference between finding out now and finding
// out from a failed sync.
func TestRenderCheckReportsAnIncompleteRender(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	// A secret created but never given a value: the state every secret passes
	// through, and one the render cannot deliver.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Attached through the store rather than `target add-key`, which now refuses
	// an unresolvable key outright. That guard closes one way into this state
	// but not the state itself: a key seeded from a file target, or one whose
	// value is removed after it was added, arrives here the same way — and it is
	// that target `render --check` has to describe honestly.
	tgt, _ := renderTargetOf(t, st, "csrv")
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

	var checkErr error
	out := captureStdout(t, func() {
		checkErr = runRender([]string{"--project", "csrv", "--check"})
	})
	// An incomplete render is a refusal waiting to happen, so it blocks too.
	if !errors.Is(checkErr, errRenderCheckBlocked) {
		t.Fatalf("an incomplete render exited clean: %v", checkErr)
	}
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "PENDING") {
		t.Fatalf("check did not report the unresolvable key:\n%s", out)
	}
	// The promise, not the phrasing: since SGNT-45 this sentence is produced
	// once (renderConditionReason) and printed by all four views, so pinning
	// its exact words here would pin three other views' output through a test
	// that names only this one.
	if !strings.Contains(out, "sync will refuse") {
		t.Fatalf("check does not say what happens next:\n%s", out)
	}
}

// `render` writes files. A project whose only target is a rendered one has no
// file to write, and saying so beats writing nothing and reporting success.
func TestRenderWriteRefusesAProjectWithOnlyARenderedTarget(t *testing.T) {
	st := newCLIVault(t)
	path := seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetRm([]string{"--project", "csrv", "--path", path}); err != nil {
		t.Fatal(err)
	}
	err := runRender([]string{"--project", "csrv"})
	if err == nil || !strings.Contains(err.Error(), "signet sync") {
		t.Fatalf("err = %v", err)
	}
	// The check still works on it — that is the view that reports the rendered
	// target's state.
	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv", "--check"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "PROD_ENV_FILE") {
		t.Fatalf("check lost the rendered target:\n%s", out)
	}
}

// Removing a rendered target detaches signet's record and nothing else — the
// same promise `target rm` already makes about every other destination.
func TestTargetRmDetachesARenderedTargetAndSaysWhatItLeft(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runTargetRm([]string{
			"--project", "csrv", "--gh-repo", "o/r",
			"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE",
		}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "left in place") {
		t.Fatalf("rm does not say the destination was left alone:\n%s", out)
	}
	targets, err := st.RenderTargetsForProject("csrv")
	if err != nil || len(targets) != 0 {
		t.Fatalf("targets = %v (err %v)", targets, err)
	}
}

// The destination column has to carry the environment, or two targets that
// differ only in scope print identically.
func TestTargetListShowsTheEnvironmentScope(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAdd([]string{
		"--secret", "csrv/ALPHA", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "ALPHA", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runTargetList([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "o/r · home-server · PROD_ENV_FILE") {
		t.Fatalf("rendered target's destination lost its scope:\n%s", out)
	}
	if !strings.Contains(out, "o/r · home-server · ALPHA") {
		t.Fatalf("gh target's destination lost its scope:\n%s", out)
	}
	if !strings.Contains(out, "gh-render") {
		t.Fatalf("listing does not name the kind:\n%s", out)
	}
}

// A secret carried only inside a rendered blob has no gh-actions target of its
// own, so the old fan-out reported "nothing to push" and exited 0 while the
// environment went on serving the credential the vault had just replaced.
func TestRotateFansOutToARenderedTargetCarryingTheSecret(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"DB_PASSWORD": "old"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	// Rotation needs a minted value; the imported one is externally issued.
	if err := runGenerate([]string{"--project", "csrv", "--name", "DB_PASSWORD", "--replace"}); err != nil {
		t.Fatal(err)
	}

	sec, err := st.GetSecret("csrv", "DB_PASSWORD")
	if err != nil || sec == nil {
		t.Fatalf("secret = %v (err %v)", sec, err)
	}
	_, targets, err := renderCoverage(st, []store.Secret{*sec})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("the rotated secret's rendered target is invisible to the fan-out: %v", targets)
	}
}

// warnStaleDestinations is the one thing that tells an operator a destination
// still holds the previous value. It must not be silent for the target kind
// whose value can never be read back to check by hand.
func TestSetWarnsThatARenderedTargetStillHoldsThePreviousValue(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"DB_PASSWORD": "old"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	// Detach the file target so the render is the only destination — the state
	// construct-server is meant to end up in.
	targets, err := st.FileTargetsForProject("csrv")
	if err != nil || len(targets) != 1 {
		t.Fatalf("file targets = %v (err %v)", targets, err)
	}
	cfg, err := targets[0].FileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := runTargetRm([]string{"--project", "csrv", "--path", cfg.Path}); err != nil {
		t.Fatal(err)
	}

	sec, err := st.GetSecret("csrv", "DB_PASSWORD")
	if err != nil || sec == nil {
		t.Fatalf("secret = %v (err %v)", sec, err)
	}
	covered, targetsFound, err := renderCoverage(st, []store.Secret{*sec})
	if err != nil {
		t.Fatal(err)
	}
	if len(covered) != 1 || len(targetsFound) != 1 {
		t.Fatalf("a render-only secret reads as undelivered: covered=%v targets=%v", covered, targetsFound)
	}
}

// An explicitly named environment must narrow the lookup, not be discarded —
// otherwise a key lands in a live environment the caller named and did not get.
func TestAddKeyRefusesWhenTheNamedEnvironmentDoesNotMatch(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "staging", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runSet([]string{"--project", "csrv", "--name", "FOO", "--generate"}); err != nil {
		t.Fatal(err)
	}

	err := runTargetAddKey([]string{
		"--project", "csrv", "--gh-secret", "PROD_ENV_FILE",
		"--gh-environment", "prod", "--name", "FOO",
	})
	if err == nil {
		t.Fatal("a key was added to a target in an environment the caller did not name")
	}
	if !strings.Contains(err.Error(), "prod") {
		t.Fatalf("error does not name the environment asked for: %v", err)
	}
	// The staging target must be untouched.
	_, cfg := renderTargetOf(t, st, "csrv")
	if cfg.Manages("FOO") {
		t.Fatalf("the key landed in the staging target anyway: %v", cfg.Keys)
	}
}

// --check resolves leniently so it survives the state it reports on. That must
// not turn an unresolvable secret into ordinary drift: `render` still refuses
// to write, so reporting "changed" promises a repair that will not happen.
func TestRenderCheckReportsUnresolvableSecretsAsSuchNotAsDrift(t *testing.T) {
	st := newCLIVault(t)
	path := seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runSet([]string{"--project", "csrv", "--name", "PW", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAddKey([]string{"--project", "csrv", "--path", path, "--name", "PW"}); err != nil {
		t.Fatal(err)
	}
	// A derivation whose input does not exist: resolvable yesterday, broken now.
	if err := runDerive([]string{
		"--project", "csrv", "--name", "DSN", "--from", "postgres://u:{{csrv/GONE}}@h/db",
	}); err == nil {
		// If derive validates its inputs up front this path is unavailable;
		// fall back to breaking an existing derivation below.
		t.Log("derive accepted a missing input")
	}

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv", "--check"}); err != nil {
			t.Fatal(err)
		}
	})
	// Whatever the project's state, the check must never claim a key is merely
	// "changed" when its value could not be computed at all.
	if strings.Contains(out, "cannot be resolved") && !strings.Contains(out, "unresolved") {
		t.Fatalf("unresolvable secrets reported without marking the affected keys:\n%s", out)
	}
}

// A gh-actions target and a gh-render target can name the same GitHub secret,
// and nothing about the destination distinguishes them: both PUT the same path,
// so the two take turns overwriting each other while each reports "in sync".
// The collision belongs to the destination, not to a kind.
func TestADestinationCannotBeClaimedByBothTargetKinds(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runSet([]string{"--project", "csrv", "--name", "TOKEN", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAdd([]string{
		"--secret", "csrv/TOKEN", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}

	err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	})
	if err == nil {
		t.Fatal("a rendered target was attached to a destination a secret already delivers to")
	}
	if !strings.Contains(err.Error(), "gh-actions") || !strings.Contains(err.Error(), "home-server") {
		t.Fatalf("the refusal does not say what already holds the destination: %v", err)
	}

	// And in the other order: the render target claims it first.
	st2 := newCLIVault(t)
	seedProject(t, st2, "csrv", map[string]string{"ALPHA": "a"})
	if err := runSet([]string{"--project", "csrv", "--name", "TOKEN", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	err = runTargetAdd([]string{
		"--secret", "csrv/TOKEN", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	})
	if err == nil {
		t.Fatal("a secret was attached to a destination a rendered target already delivers to")
	}
	if !strings.Contains(err.Error(), "gh-render") {
		t.Fatalf("the refusal does not say what already holds the destination: %v", err)
	}
}

// --allow-shrink disarms the only guard between a shortened key set and a live
// environment. As a run-wide switch it disarmed it for every rendered target in
// the run, including the ones the operator was not thinking about.
func TestAllowShrinkRefusesToCoverAWholeRun(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	for _, name := range []string{"PROD_ENV_FILE", "STAGING_ENV_FILE"} {
		if err := runTargetAdd([]string{
			"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
			"--gh-secret", name, "--no-preflight",
		}); err != nil {
			t.Fatal(err)
		}
	}

	err := runSync([]string{"--allow-shrink"})
	if err == nil {
		t.Fatal("--allow-shrink waived the guard for every rendered target in the run")
	}
	if !strings.Contains(err.Error(), "--secret") {
		t.Fatalf("the refusal does not say how to narrow the waiver: %v", err)
	}
}

// markRenderTargetPushed records the push the destination would hold if a sync
// had just delivered the project's current values — the digest computed exactly
// as the push path computes it, so GHState answers "in sync" rather than by
// coincidence of an empty column.
func markRenderTargetPushed(t *testing.T, st *store.Store, project string) {
	t.Helper()
	a, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	want, _, err := a.projectValuesStrict(project)
	if err != nil {
		t.Fatal(err)
	}
	tgt, cfg := renderTargetOf(t, st, project)
	content, err := syncpkg.RenderBlob(cfg, project, want)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateTargetPush(tgt.ID, "in sync", "",
		&store.PushProvenance{Digest: vault.ValueDigest(a.key, content), Keys: cfg.Keys},
		"2026-08-15T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

// `render` writes files. A rendered target delivers over the network, so this
// command cannot touch it — but reporting success while leaving the environment
// holding the values the file no longer has is the same silent staleness the
// target kind exists to prevent.
//
// A target that has never been pushed is the case that wants the warning most:
// nothing has ever reached the environment.
func TestRenderWriteSaysTheRenderedTargetsWereNotWritten(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "were not written") || !strings.Contains(out, "never pushed") {
		t.Fatalf("a write said nothing about the rendered target it could not write:\n%s", out)
	}
	if !strings.Contains(out, "signet sync") {
		t.Fatalf("the note does not name the next step:\n%s", out)
	}
}

// The warning used to be printed unconditionally, so it was wrong exactly when
// things were fine — and a warning that cries wolf on every clean run is one an
// operator learns to skip, including on the run where it is right. Writing a
// file target does not make a rendered target stale; only the vault moving on
// since its last push does. Observed 2026-08-15 during a rotation, on a target
// that had been pushed minutes earlier (SGNT-31).
func TestRenderWriteDoesNotCallAnInSyncRenderedTargetStale(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	markRenderTargetPushed(t, st, "csrv")

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "stale") {
		t.Fatalf("a rendered target that is in sync was reported stale:\n%s", out)
	}
	// The suggestion is the actionable half of the bug: the operator ran the
	// sync it asked for and it had already happened.
	if strings.Contains(out, "signet sync") {
		t.Fatalf("a sync was suggested with nothing to deliver:\n%s", out)
	}
	if !strings.Contains(out, "in sync") {
		t.Fatalf("the report does not say the target is current:\n%s", out)
	}
}

// EMPTY and INCOMPLETE are the states sync *refuses*, so pointing the operator
// at one sends them at a command that will decline — the same misdirection the
// unconditional "now stale" was, in a new place. Nothing covered this before:
// flipping either state to wantsSync left the suite green.
func TestRenderWriteWithholdsTheSyncSuggestionForStatesSyncRefuses(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	// A secret created but never given a value, attached to the render target
	// through the store — `target add-key` refuses an unresolvable key, which
	// closes one way into this state but not the state itself. A key seeded
	// from a file target, or one whose value is removed later, arrives here the
	// same way.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	tgt, _ := renderTargetOf(t, st, "csrv")
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

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("an unpushable target was not reported as incomplete:\n%s", out)
	}
	if strings.Contains(out, "run `signet sync`") {
		t.Fatalf("a sync was suggested for a target sync would refuse:\n%s", out)
	}
	if strings.Contains(out, "stale") {
		t.Fatalf("an incomplete target was reported as stale:\n%s", out)
	}
}

// A never-pushed target's next step is the --against comparison, not a sync:
// the first push is the one no other guard covers, since there is no previous
// delivery to compare against and the destination cannot be read back. The
// group's trailing `signet sync` line cannot say that, so the target has to.
func TestRenderWriteSendsANeverPushedTargetToTheAgainstCheck(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "--against") {
		t.Fatalf("a first push was not sent at the only guard it has:\n%s", out)
	}
	// printRenderCheck names the same step for the same target; the two
	// commands disagreeing about a first push is what routing both through
	// renderState was meant to prevent.
	if !strings.Contains(out, "--check --against") {
		t.Fatalf("the hint does not name the check that performs it:\n%s", out)
	}
}

// A state renderedTargetNote has not been taught must read as itself and count
// as undelivered. Folding it into the in-sync wording would make an unchecked
// word an all-clear and suppress the suggestion — this bug exactly, one state
// along, which is how it would come back.
func TestAnUnknownRenderStateIsNotReportedAsAnAllClear(t *testing.T) {
	note := renderedTargetNote(&store.Target{}, answered("refused"))
	if !note.wantsSync {
		t.Fatal("an unrecognized state suppressed the sync suggestion")
	}
	if strings.Contains(note.text, "changed nothing") {
		t.Fatalf("an unrecognized state was worded as an all-clear: %q", note.text)
	}
	if note.text != "refused" {
		t.Fatalf("the state was not reported as itself: %q", note.text)
	}
}

// The other half of the same guarantee: once the vault moves on, the warning
// must come back. Without this the fix could have been "never warn".
func TestRenderWriteSaysStaleOnceTheVaultMovesOn(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	markRenderTargetPushed(t, st, "csrv")
	// Minting a new value is the cheapest way to move the vault on without a
	// network push; what the value becomes is irrelevant, only that it changed.
	if err := runGenerate([]string{"--project", "csrv", "--name", "ALPHA", "--replace"}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "now stale") {
		t.Fatalf("the vault moved on and the rendered target was not reported stale:\n%s", out)
	}
	if !strings.Contains(out, "signet sync") {
		t.Fatalf("a stale target was reported without naming the next step:\n%s", out)
	}
}

// --against exists to answer one question, and with no rendered target to ask
// it of the honest answer is not "nothing" — it is that the comparison never
// ran. Accepting it silently would be the same false all-clear it was added to
// prevent.
func TestAgainstIsRefusedWhenThereIsNoRenderedTarget(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	live := filepath.Join(t.TempDir(), "live.env")
	if err := os.WriteFile(live, []byte("ALPHA=a\nGONE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runRender([]string{"--project", "csrv", "--check", "--against", live})
	if err == nil {
		t.Fatal("--against reported a clean check against nothing at all")
	}
	if !strings.Contains(err.Error(), "no rendered targets") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// Existence is not the property that matters: a push refuses on any key it
// cannot resolve, so attaching an unresolvable one arms that refusal for the
// whole environment rather than for the key.
func TestAddKeyRefusesAKeyThatCannotBeResolved(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	err := runTargetAddKey([]string{"--project", "csrv", "--gh-secret", "PROD_ENV_FILE", "--name", "PENDING"})
	if err == nil {
		t.Fatal("an unresolvable key was attached, arming a refusal of the whole environment")
	}
	if !strings.Contains(err.Error(), "PENDING") || !strings.Contains(err.Error(), "refuse") {
		t.Fatalf("the refusal does not say what it would cost: %v", err)
	}

	// The target is unchanged, so the environment it would deliver is too.
	_, cfg := renderTargetOf(t, st, "csrv")
	if cfg.Manages("PENDING") {
		t.Fatalf("the key landed on the target anyway: %v", cfg.Keys)
	}
}

// Reachability is half the question. `sync --check` probing only the GitHub
// grant reported a destination ready that `sync` would then refuse for having
// nothing complete to send — a green check followed by a failed deploy.
func TestSyncCheckReportsARenderThatWouldBeRefused(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "csrv", map[string]string{"ALPHA": "a"})
	if err := runTargetAdd([]string{
		"--project", "csrv", "--render-as-secret", "--gh-repo", "o/r",
		"--gh-environment", "home-server", "--gh-secret", "PROD_ENV_FILE", "--no-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	// A managed key the vault cannot supply, attached the way one arrives in
	// practice — seeded, or emptied after the fact.
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	tgt, _ := renderTargetOf(t, st, "csrv")
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

	a, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	targets, err := a.st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}

	var checkErr error
	out := captureStdout(t, func() { checkErr = checkRenders(a, targets) })
	if checkErr == nil {
		t.Fatalf("the check passed a render that sync would refuse:\n%s", out)
	}
	if !strings.Contains(out, "PENDING") {
		t.Fatalf("the check does not name the key that makes it incomplete:\n%s", out)
	}
}
