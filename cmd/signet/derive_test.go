package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/sync"
)

// setValue drives `signet set` with a value on stdin, the way the CLI is used.
func setValue(t *testing.T, project, name, value string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "in")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	prev := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = prev }()
	if err := runSet([]string{"--project", project, "--name", name}); err != nil {
		t.Fatal(err)
	}
}

// This is SGNT-18's motivating bug, end to end.
//
// Before derived secrets, drydock/DRYDOCK_DATABASE_URL was a hand-composed
// value embedding construct-server/DRYDOCK_DB_PASSWORD. Rotating the password
// left the DSN silently wrong, and `render --check` reported the file in sync,
// because the file matched what the vault held — each entry individually
// correct, the pair incoherent. The one tool whose job is noticing divergence
// structurally could not notice this one.
func TestDerivedValueFollowsARotatedInputAcrossProjects(t *testing.T) {
	st := newCLIVault(t)
	dir := t.TempDir()
	env := filepath.Join(dir, "drydock.env")

	setValue(t, "construct-server", "DRYDOCK_DB_PASSWORD", "hunter2")
	if err := os.WriteFile(env, []byte("DRYDOCK_DATABASE_URL=placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", "drydock", env}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{
		"--project", "drydock", "--name", "DRYDOCK_DATABASE_URL", "--replace",
		"--from", "postgres://u:{{construct-server/DRYDOCK_DB_PASSWORD}}@h:5432/drydock",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, env); !strings.Contains(got, "hunter2") {
		t.Fatalf("first render did not compose the password: %q", got)
	}

	// Rotate the input, in a different project, touching nothing in drydock.
	setValue(t, "construct-server", "DRYDOCK_DB_PASSWORD", "rotated99")

	// The assertion that would have failed before this feature: the file is now
	// stale, and check has to say so.
	drift := sync.CheckFile(env, mustValues(t, st), []string{"DRYDOCK_DATABASE_URL"})
	changed := false
	for _, k := range drift.Keys {
		if k.Key == "DRYDOCK_DATABASE_URL" && k.State == "changed" {
			changed = true
		}
	}
	if !changed {
		t.Fatalf("render --check reported no drift after the input rotated — the silent-drift bug; states were %+v", drift.Keys)
	}

	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, env)
	if !strings.Contains(got, "rotated99") || strings.Contains(got, "hunter2") {
		t.Errorf("second render did not follow the rotation: %q", got)
	}
}

// mustValues resolves drydock's project values the way render does.
func mustValues(t *testing.T, st *store.Store) map[string]string {
	t.Helper()
	a, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	v, _, err := a.projectValues("drydock")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The invariant the whole feature rests on. A settable derived secret is just
// the original bug with extra steps: a stored copy that can drift from the
// inputs it claims to be composed from.
func TestSetRefusesADerivedSecret(t *testing.T) {
	newCLIVault(t)
	setValue(t, "p", "PW", "x")
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--from", "u:{{PW}}"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "in")
	if err := os.WriteFile(path, []byte("override\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	prev := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = prev }()

	err = runSet([]string{"--project", "p", "--name", "DSN"})
	if err == nil {
		t.Fatal("set overwrote a derived secret")
	}
	// The message has to name the way out, not just the refusal.
	if !strings.Contains(err.Error(), "derive") {
		t.Errorf("refusal does not point at the operation to use instead: %v", err)
	}
}

// Converting a stored secret discards a value that may be live somewhere signet
// cannot see, so it has to be asked for rather than assumed.
func TestDeriveRefusesToConvertAStoredSecretWithoutReplace(t *testing.T) {
	newCLIVault(t)
	setValue(t, "p", "DSN", "postgres://hand-written")

	err := runDerive([]string{"--project", "p", "--name", "DSN", "--from", "u:{{OTHER}}"})
	if err == nil {
		t.Fatal("derive silently replaced a stored value")
	}
	if !strings.Contains(err.Error(), "--replace") {
		t.Errorf("refusal does not name the flag that permits it: %v", err)
	}
}

// A derivation that cannot resolve is a secret that fails every render from now
// on. Rejecting it at declaration time is the only moment it is cheap to fix.
func TestDeriveRejectsAnUnresolvableTemplate(t *testing.T) {
	newCLIVault(t)
	err := runDerive([]string{"--project", "p", "--name", "DSN", "--from", "u:{{p/NOPE}}"})
	if err == nil {
		t.Fatal("derive accepted a template naming a secret that does not exist")
	}
	if !strings.Contains(err.Error(), "not saved") {
		t.Errorf("error does not say the derivation was rejected: %v", err)
	}
}

// resolve.Dependents is what makes a rotation able to say what else it changed.
// The bare-reference case is the one a SQL LIKE would get wrong.
func TestDependentsResolvesBareAndCrossProjectRefs(t *testing.T) {
	st := newCLIVault(t)
	setValue(t, "construct-server", "PW", "x")
	setValue(t, "drydock", "PW", "y")

	if err := runDerive([]string{"--project", "drydock", "--name", "CROSS",
		"--from", "a:{{construct-server/PW}}"}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "drydock", "--name", "BARE",
		"--from", "b:{{PW}}"}); err != nil {
		t.Fatal(err)
	}

	// A bare {{PW}} inside drydock means drydock/PW — not construct-server/PW,
	// which is what a text match on the template would have concluded.
	deps, err := resolve.Dependents(st, "construct-server", "PW")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "CROSS" {
		t.Fatalf("construct-server/PW dependents = %v, want just CROSS", names(deps))
	}
	deps, err = resolve.Dependents(st, "drydock", "PW")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "BARE" {
		t.Fatalf("drydock/PW dependents = %v, want just BARE", names(deps))
	}
}

func names(secs []store.Secret) []string {
	out := make([]string, len(secs))
	for i, s := range secs {
		out[i] = s.Project + "/" + s.Name
	}
	return out
}

// Re-importing an env file signet rendered is the likeliest way to break the
// "nothing is stored" invariant from outside `set`: the file contains the
// resolved value by construction, and import would write it back as a version.
func TestImportLeavesDerivedSecretsAlone(t *testing.T) {
	st := newCLIVault(t)
	dir := t.TempDir()
	env := filepath.Join(dir, "p.env")

	setValue(t, "p", "PW", "hunter2")
	if err := os.WriteFile(env, []byte("DSN=placeholder\nOTHER=keepme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", "p", env}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--replace",
		"--from", "u:{{PW}}@h"}); err != nil {
		t.Fatal(err)
	}
	if err := runRender([]string{"--project", "p"}); err != nil {
		t.Fatal(err)
	}

	// Import the file signet just wrote.
	if err := runImport([]string{"--project", "p", env}); err != nil {
		t.Fatal(err)
	}

	sec, err := st.GetSecret("p", "DSN")
	if err != nil {
		t.Fatal(err)
	}
	if !sec.Derived() {
		t.Fatal("import overwrote a derived secret's derivation")
	}
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	// It had one stored version from before the conversion; import must not
	// have added a second holding the composed credential.
	if cur != nil && cur.VersionNo != 1 {
		t.Errorf("import stored version %d onto a derived secret", cur.VersionNo)
	}
	// The unrelated key still imports — the guard is per-key, not per-file.
	if other, _ := st.GetSecret("p", "OTHER"); other == nil {
		t.Error("the derived guard stopped the rest of the file importing")
	}
}

// Keeping a converted secret's old versions is only a real safety net if they
// can be reached again; otherwise the comment justifying it describes data
// nothing can read.
func TestClearDerivationRestoresTheStoredValue(t *testing.T) {
	st := newCLIVault(t)
	setValue(t, "p", "PW", "x")
	setValue(t, "p", "DSN", "hand-written")
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--replace",
		"--from", "u:{{PW}}@h"}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--clear"}); err != nil {
		t.Fatal(err)
	}

	sec, err := st.GetSecret("p", "DSN")
	if err != nil {
		t.Fatal(err)
	}
	if sec.Derived() {
		t.Fatal("--clear left the secret derived")
	}
	a, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	r, err := resolve.Current(a.st, a.key, sec)
	if err != nil {
		t.Fatal(err)
	}
	if v := r.Value; v != "hand-written" {
		t.Errorf("cleared secret resolves to %q, want the stored value back", v)
	}
}

// A secret created as derived has no stored value to fall back to, and signet
// cannot delete a secret — so clearing it would strand an entry with no value
// and no way to remove it.
func TestClearRefusesWhenThereIsNoStoredValue(t *testing.T) {
	newCLIVault(t)
	setValue(t, "p", "PW", "x")
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--from", "u:{{PW}}@h"}); err != nil {
		t.Fatal(err)
	}
	err := runDerive([]string{"--project", "p", "--name", "DSN", "--clear"})
	if err == nil {
		t.Fatal("--clear stranded a secret with no value")
	}
	if !strings.Contains(err.Error(), "no stored value") {
		t.Errorf("refusal does not explain why: %v", err)
	}
}
