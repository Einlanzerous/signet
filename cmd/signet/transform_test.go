package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/sync"
)

// captureStderr is captureStdout for the stream `reveal` explains itself on.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// seedDrydockHash is the SGNT-22 case: a Drydock env file managing
// DRYDOCK_AUTH_PASSWORD_HASH, whose value is the scrypt of a password that
// lives in the vault as an ordinary secret.
func seedDrydockHash(t *testing.T, password string) (env string) {
	t.Helper()
	env = filepath.Join(t.TempDir(), "drydock.env")
	if err := os.WriteFile(env, []byte("DRYDOCK_AUTH_PASSWORD_HASH=placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", "drydock", env}); err != nil {
		t.Fatal(err)
	}
	setValue(t, "drydock", "DRYDOCK_AUTH_PASSWORD", password)
	if err := runDerive([]string{
		"--project", "drydock", "--name", "DRYDOCK_AUTH_PASSWORD_HASH", "--replace",
		"--from", "{{DRYDOCK_AUTH_PASSWORD | scrypt}}",
	}); err != nil {
		t.Fatal(err)
	}
	return env
}

func hashLine(t *testing.T, env string) string {
	t.Helper()
	for _, line := range strings.Split(readFile(t, env), "\n") {
		if v, ok := strings.CutPrefix(line, "DRYDOCK_AUTH_PASSWORD_HASH="); ok {
			return v
		}
	}
	t.Fatalf("no DRYDOCK_AUTH_PASSWORD_HASH in %s:\n%s", env, readFile(t, env))
	return ""
}

// The acceptance criterion the ticket is most afraid of. A salted hash that
// changes on every render makes `render --check` report permanent drift, which
// is SGNT-18's silent-drift bug turned into a loud one — and loud drift is
// drift an operator learns to ignore.
func TestRenderingAScryptDerivedSecretTwiceReportsNoDrift(t *testing.T) {
	st := newCLIVault(t)
	env := seedDrydockHash(t, "hunter2")

	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	first := hashLine(t, env)
	if !strings.HasPrefix(first, "scrypt$16384$8$1$") {
		t.Fatalf("rendered %q, want a Drydock scrypt hash", first)
	}

	// Second render, unchanged vault: same bytes.
	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	if second := hashLine(t, env); second != first {
		t.Fatalf("an unchanged vault rendered two different hashes:\n  %s\n  %s", first, second)
	}

	// And the report a deploy script gates on agrees. Both views: the library
	// check the mirror uses, and the command itself.
	drift := sync.CheckFile(env, mustValues(t, st), []string{"DRYDOCK_AUTH_PASSWORD_HASH"})
	for _, k := range drift.Keys {
		if k.State != "ok" {
			t.Errorf("key %s is %q after rendering twice, want ok", k.Key, k.State)
		}
	}
	var checkErr error
	out := captureStdout(t, func() {
		checkErr = runRender([]string{"--project", "drydock", "--check"})
	})
	if checkErr != nil {
		t.Errorf("`render --check` failed on an unchanged vault: %v\n%s", checkErr, out)
	}
	if strings.Contains(out, "changed") || strings.Contains(out, "missing") {
		t.Errorf("`render --check` reports drift on an unchanged vault:\n%s", out)
	}
}

// The converse, which a transform must not break: hashing an input is not a way
// to hide that it moved. Rotating the password has to show up as drift on the
// hash, and a render has to follow it.
func TestRotatingTheHashedPasswordIsDriftOnTheHash(t *testing.T) {
	st := newCLIVault(t)
	env := seedDrydockHash(t, "hunter2")
	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	before := hashLine(t, env)

	setValue(t, "drydock", "DRYDOCK_AUTH_PASSWORD", "rotated99")

	drift := sync.CheckFile(env, mustValues(t, st), []string{"DRYDOCK_AUTH_PASSWORD_HASH"})
	if len(drift.Keys) != 1 || drift.Keys[0].State != "changed" {
		t.Fatalf("render --check missed a rotated input behind a hash: %+v", drift.Keys)
	}
	if err := runRender([]string{"--project", "drydock"}); err != nil {
		t.Fatal(err)
	}
	after := hashLine(t, env)
	if after == before {
		t.Fatal("the hash did not follow its input")
	}
	// The salt moved with it: reusing one across a rotation is the weakening the
	// ticket names for a salt held constant per secret.
	if strings.Split(after, "$")[4] == strings.Split(before, "$")[4] {
		t.Error("the salt survived a password rotation")
	}
}

// Declaration is where a transform that cannot be made deterministic has to be
// stopped — not at the second render, by which time the secret is saved and
// every check against it is noise.
func TestDeriveRejectsTransformsThatCannotBeDeterministicAndSavesNothing(t *testing.T) {
	st := newCLIVault(t)
	setValue(t, "drydock", "DRYDOCK_AUTH_PASSWORD", "hunter2")

	for name, want := range map[string][]string{
		"bcrypt": {"bcrypt", "drift", "scrypt"},
		"rot13":  {"rot13", "unknown", "base64"},
	} {
		err := runDerive([]string{"--project", "drydock", "--name", "HASH_" + name,
			"--from", "{{DRYDOCK_AUTH_PASSWORD | " + name + "}}"})
		if err == nil {
			t.Fatalf("derive accepted a %s transform", name)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not mention %q", name, err, w)
			}
		}
		if sec, _ := st.GetSecret("drydock", "HASH_"+name); sec != nil {
			t.Errorf("%s: a rejected derivation left a secret behind", name)
		}
	}
}

// Declaring resolves the template once, transforms included, so a derivation
// that cannot produce a value is refused while the operator is still looking at
// it rather than failing every render afterwards.
func TestDeriveResolvesATransformedTemplateBeforeSavingIt(t *testing.T) {
	st := newCLIVault(t)
	err := runDerive([]string{"--project", "drydock", "--name", "HASH", "--from", "{{NOPE | scrypt}}"})
	if err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("derive of a transform over a missing input: %v", err)
	}
	if sec, _ := st.GetSecret("drydock", "HASH"); sec != nil {
		t.Error("a derivation that could not resolve was saved")
	}
}

// The derive verb prints what the secret is built from. A hash listed as a bare
// input reads as the password being copied in.
func TestDeriveShowsWhichInputsAreTransformed(t *testing.T) {
	newCLIVault(t)
	setValue(t, "drydock", "PW", "hunter2")
	setValue(t, "drydock", "USER", "owner")
	var err error
	out := captureStdout(t, func() {
		err = runDerive([]string{"--project", "drydock", "--name", "LOGIN",
			"--from", "{{USER}}:{{PW | scrypt}}"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"← drydock/USER\n", "← drydock/PW (scrypt)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("derive output does not contain %q:\n%s", want, out)
		}
	}
}

// reveal explains where a composed value came from, and a hash is no exception:
// the provenance names the template with its transform, and the ledger records
// the reveal against the input too — a scrypt of a password discloses less than
// the password, but the rule is per-input and not per-strength.
func TestRevealOfATransformedSecretExplainsItsProvenance(t *testing.T) {
	st := newCLIVault(t)
	seedDrydockHash(t, "hunter2")

	var revealErr error
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			revealErr = runReveal([]string{"--project", "drydock", "--name", "DRYDOCK_AUTH_PASSWORD_HASH"})
		})
	})
	if revealErr != nil {
		t.Fatal(revealErr)
	}
	if !strings.HasPrefix(stdout, "scrypt$16384$8$1$") {
		t.Errorf("reveal printed %q, want the hash alone on stdout", stdout)
	}
	if strings.Contains(stdout, "hunter2") {
		t.Errorf("reveal of the hash printed the password: %q", stdout)
	}
	const tmpl = "{{DRYDOCK_AUTH_PASSWORD | scrypt}}"
	if !strings.Contains(stderr, "derived from: "+tmpl) {
		t.Errorf("provenance on stderr does not name the template with its transform:\n%s", stderr)
	}

	hash := mustSecret(t, st, "drydock", "DRYDOCK_AUTH_PASSWORD_HASH")
	direct, err := st.ListAudit(0, hash.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ledgerHas(direct, "secret.reveal", tmpl) {
		t.Errorf("the reveal's ledger entry does not carry the derivation: %+v", direct)
	}
	input := mustSecret(t, st, "drydock", "DRYDOCK_AUTH_PASSWORD")
	inputs, err := st.ListAudit(0, input.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ledgerHas(inputs, "secret.reveal", "derives from it") {
		t.Errorf("revealing the hash left the password's own ledger silent: %+v", inputs)
	}
	for _, e := range append(direct, inputs...) {
		if strings.Contains(e.Details, "hunter2") || strings.Contains(e.Details, "scrypt$") {
			t.Errorf("a ledger entry carries a value: %q", e.Details)
		}
	}
}

func ledgerHas(entries []store.AuditEntry, action, detail string) bool {
	for _, e := range entries {
		if e.Action == action && strings.Contains(e.Details, detail) {
			return true
		}
	}
	return false
}

// Rotation reports what else changed, and it walks Refs. A transformed
// reference dropping out of that graph would report a hashed input as an input
// of nothing — the under-reporting derivations exist to prevent.
func TestDependentsIncludeASecretThatHashesTheInput(t *testing.T) {
	st := newCLIVault(t)
	seedDrydockHash(t, "hunter2")
	deps, err := resolve.Dependents(st, "drydock", "DRYDOCK_AUTH_PASSWORD")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(deps); len(got) != 1 || got[0] != "drydock/DRYDOCK_AUTH_PASSWORD_HASH" {
		t.Fatalf("dependents of the password = %v, want the hash", got)
	}
}

// The usage text is what an operator reads before trying bcrypt. It is built from
// the registry, so it has to name what is refused as well as what is accepted.
func TestDeriveUsageNamesTheDeclarableAndTheRefusedTransforms(t *testing.T) {
	newCLIVault(t)
	err := runDerive([]string{"--project", "p", "--name", "N"})
	if err == nil {
		t.Fatal("derive with no template succeeded")
	}
	for _, want := range []string{"base64", "hex", "scrypt", "bcrypt", "drift"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("usage does not mention %q:\n%s", want, err)
		}
	}
}
