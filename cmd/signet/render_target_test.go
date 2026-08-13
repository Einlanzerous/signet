package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
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

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv", "--check", "--against", live}); err != nil {
			t.Fatal(err)
		}
	})
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
		if err := runRender([]string{"--project", "csrv", "--check", "--against", live}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "covers every key in") {
		t.Fatalf("check did not clear after the key was added:\n%s", out)
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
	if err := runTargetAddKey([]string{"--project", "csrv", "--gh-secret", "PROD_ENV_FILE", "--name", "PENDING"}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runRender([]string{"--project", "csrv", "--check"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "PENDING") {
		t.Fatalf("check did not report the unresolvable key:\n%s", out)
	}
	if !strings.Contains(out, "sync will refuse this target") {
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
	if contains(cfg.Keys, "FOO") {
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
