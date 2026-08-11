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

	sec := mustSecret(t, st, "p", "DSN")
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

	sec := mustSecret(t, st, "p", "DSN")
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

// The reason `generate` is a verb: the permission allowlist matches command
// prefixes, so a flag whose position is free cannot be gated. These assert the
// verb does what the flag did, so the allowlist can grant one without the other.
func TestGenerateVerbMintsAndMarksRotatable(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	sec := mustSecret(t, st, "p", "TOK")
	// Generated is what makes a secret rotatable; a value minted by signet that
	// did not record this would be unrotatable for no reason.
	if !sec.Generated {
		t.Error("generate did not mark the secret as signet-minted")
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
	if len(r.Value) != 32 {
		t.Errorf("generated value is %d chars, want 32", len(r.Value))
	}
}

func TestGenerateAcceptsExpiry(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "p", "TOK"), day(t, "2026-10-19"); got != want {
		t.Errorf("expiry = %q, want %q", got, want)
	}
}

// mustSecret fetches a secret that the test requires to exist, so a nil result
// fails here rather than as a nil dereference three lines later.
func mustSecret(t *testing.T, st *store.Store, project, name string) *store.Secret {
	t.Helper()
	sec, err := st.GetSecret(project, name)
	if err != nil {
		t.Fatal(err)
	}
	if sec == nil {
		t.Fatalf("no secret %s/%s", project, name)
	}
	return sec
}

// set --generate has to keep working: it is in the README and in muscle memory.
func TestSetGenerateStillWorks(t *testing.T) {
	st := newCLIVault(t)
	if err := runSet([]string{"--project", "p", "--name", "TOK", "--generate"}); err != nil {
		t.Fatal(err)
	}
	if !mustSecret(t, st, "p", "TOK").Generated {
		t.Error("set --generate no longer mints a rotatable secret")
	}
}

// Rotation existed only on the HTTP API, which meant reaching it required a
// bearer token on a command line. The CLI verb has to refuse exactly what the
// API refuses, or the two surfaces disagree about the same question.
func TestRotateMintsANewVersion(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	sec := mustSecret(t, st, "p", "TOK")
	before, err := st.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := runRotate([]string{"--secret", "p/TOK"}); err != nil {
		t.Fatal(err)
	}
	after, err := st.CurrentVersion(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.VersionNo != before.VersionNo+1 {
		t.Errorf("version %d → %d, want an increment", before.VersionNo, after.VersionNo)
	}
	if after.VHash == before.VHash {
		t.Error("rotation produced the same value")
	}
}

func TestRotateRefusesExternallyIssuedSecrets(t *testing.T) {
	newCLIVault(t)
	setValue(t, "p", "PAT", "ghp_issued_elsewhere")
	err := runRotate([]string{"--secret", "p/PAT"})
	if err == nil {
		t.Fatal("rotate minted a new value for an externally-issued secret")
	}
	// Same reasoning the API gives: signet can fan out, not mint.
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("refusal does not explain why: %v", err)
	}
}

func TestRotateRefusesDerivedSecrets(t *testing.T) {
	newCLIVault(t)
	setValue(t, "p", "PW", "x")
	if err := runDerive([]string{"--project", "p", "--name", "DSN", "--from", "u:{{PW}}"}); err != nil {
		t.Fatal(err)
	}
	err := runRotate([]string{"--secret", "p/DSN"})
	if err == nil {
		t.Fatal("rotate acted on a derived secret")
	}
	// Must not fall through to the externally-issued message, which would tell
	// the operator to rotate at an issuer that does not exist.
	if strings.Contains(err.Error(), "issuer") {
		t.Errorf("derived secret got the externally-issued advice: %v", err)
	}
	if !strings.Contains(err.Error(), "inputs") {
		t.Errorf("refusal does not say what to rotate instead: %v", err)
	}
}

// A rotation changes every derived secret built on it, at the same instant —
// that is the property, and it is worth asserting rather than asserting that a
// message about it was printed.
func TestRotateMovesEveryDerivedSecretBuiltOnIt(t *testing.T) {
	newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "PW"}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "q", "--name", "DSN", "--from", "u:{{p/PW}}@h"}); err != nil {
		t.Fatal(err)
	}

	resolved := func() string {
		t.Helper()
		a, err := setup()
		if err != nil {
			t.Fatal(err)
		}
		defer a.close()
		sec, err := a.st.GetSecret("q", "DSN")
		if err != nil {
			t.Fatal(err)
		}
		r, err := resolve.Current(a.st, a.key, sec)
		if err != nil {
			t.Fatal(err)
		}
		return r.Value
	}

	before := resolved()
	if err := runRotate([]string{"--secret", "p/PW"}); err != nil {
		t.Fatal(err)
	}
	if after := resolved(); after == before {
		t.Error("rotating an input left the derived secret unchanged")
	}
}

// `generated` decides whether rotate may mint a replacement, so it has to
// describe the CURRENT value, not the secret's origin. CreateSecret was its
// only writer, which broke it in both directions.
func TestGeneratedTracksTheCurrentValueNotTheOrigin(t *testing.T) {
	t.Run("set over a minted value clears it", func(t *testing.T) {
		st := newCLIVault(t)
		if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
			t.Fatal(err)
		}
		// Overwrite with a value from outside — an externally-issued credential.
		setValue(t, "p", "TOK", "ghp_issued_elsewhere")

		if mustSecret(t, st, "p", "TOK").Generated {
			t.Fatal("secret still reads as signet-minted after being set from stdin")
		}
		// The consequence: rotate would otherwise mint over a live credential.
		if err := runRotate([]string{"--secret", "p/TOK"}); err == nil {
			t.Error("rotate minted over an externally-issued value")
		}
	})

	t.Run("generate over an issued value sets it", func(t *testing.T) {
		st := newCLIVault(t)
		setValue(t, "p", "TOK", "ghp_issued_elsewhere")
		if err := runGenerate([]string{"--project", "p", "--name", "TOK", "--replace"}); err != nil {
			t.Fatal(err)
		}
		if !mustSecret(t, st, "p", "TOK").Generated {
			t.Fatal("value signet just minted does not read as minted")
		}
		// The consequence: it would otherwise be permanently unrotatable.
		if err := runRotate([]string{"--secret", "p/TOK", "--no-sync"}); err != nil {
			t.Errorf("signet cannot rotate a value it minted itself: %v", err)
		}
	})
}

// generate is granted to agents wholesale, so it is the verb that must not be
// able to replace a live credential with a random string by accident.
func TestGenerateRefusesToOverwriteWithoutReplace(t *testing.T) {
	st := newCLIVault(t)
	setValue(t, "p", "PAT", "ghp_live_credential")

	err := runGenerate([]string{"--project", "p", "--name", "PAT"})
	if err == nil {
		t.Fatal("generate clobbered a live externally-issued value")
	}
	if !strings.Contains(err.Error(), "--replace") {
		t.Errorf("refusal does not name the flag that permits it: %v", err)
	}
	a, err2 := setup()
	if err2 != nil {
		t.Fatal(err2)
	}
	defer a.close()
	r, err2 := resolve.Current(a.st, a.key, mustSecret(t, st, "p", "PAT"))
	if err2 != nil {
		t.Fatal(err2)
	}
	if r.Value != "ghp_live_credential" {
		t.Errorf("value changed despite the refusal: %q", r.Value)
	}
}

// On an already-minted secret the useful advice is `rotate`, not `--replace`:
// rotate also pushes, which is almost always what was wanted.
func TestGenerateOnAMintedSecretPointsAtRotate(t *testing.T) {
	newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	err := runGenerate([]string{"--project", "p", "--name", "TOK"})
	if err == nil {
		t.Fatal("generate silently re-minted")
	}
	if !strings.Contains(err.Error(), "rotate") {
		t.Errorf("refusal does not point at rotate: %v", err)
	}
}

// A registered-but-never-written secret has nothing to lose, and creating one
// then filling it is the ordinary flow.
func TestGenerateFillsARegisteredSecretWithoutReplace(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "NEW"}); err != nil {
		t.Fatalf("generate refused a secret that does not exist yet: %v", err)
	}
	if !mustSecret(t, st, "p", "NEW").Generated {
		t.Error("generate did not mark the new secret as minted")
	}
}

// A rotation moves the value; leaving the expiry to describe the version it
// replaced is the silent half of the bug `set --expires` was fixed for.
func TestRotateMovesExpiryWhenAsked(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if err := runRotate([]string{"--secret", "p/TOK", "--expires", "2027-01-31", "--no-sync"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "p", "TOK"), day(t, "2027-01-31"); got != want {
		t.Errorf("expiry = %q, want %q", got, want)
	}
	if err := runRotate([]string{"--secret", "p/TOK", "--expires", "", "--no-sync"}); err != nil {
		t.Fatal(err)
	}
	if got := expiryOf(t, st, "p", "TOK"); got != "" {
		t.Errorf("explicit empty --expires did not clear the expiry: %q", got)
	}
}

// Without the flag the expiry stays put — that is a choice, not a silent drop,
// and rotate must not invent one.
func TestRotateLeavesExpiryAloneWithoutTheFlag(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK", "--expires", "2026-10-19"}); err != nil {
		t.Fatal(err)
	}
	if err := runRotate([]string{"--secret", "p/TOK", "--no-sync"}); err != nil {
		t.Fatal(err)
	}
	if got, want := expiryOf(t, st, "p", "TOK"), day(t, "2026-10-19"); got != want {
		t.Errorf("expiry = %q, want it unchanged at %q", got, want)
	}
}

// A derived secret with its own GitHub destination holds a value composed from
// the rotated one, so it changed at the same instant. Pushing only the rotated
// secret leaves that destination serving a value built from the previous
// version, with the command exiting 0 — the drydock DSN hazard, reached
// through rotation instead of through a stale stored copy.
func TestRotationFansOutToDerivedSecretsWithTheirOwnTargets(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "csrv", "--name", "PW"}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "drydock", "--name", "DSN",
		"--from", "u:{{csrv/PW}}@h"}); err != nil {
		t.Fatal(err)
	}
	// Only the derived secret has a destination — the rotated one has none, so
	// a fan-out that started from the rotated secret's targets would push
	// nothing at all.
	dsn := mustSecret(t, st, "drydock", "DSN")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if _, err := m.AddGHTarget(dsn.ID, "Einlanzerous/drydock", "DSN"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "target.add", SecretID: dsn.ID,
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}

	pw := mustSecret(t, st, "csrv", "PW")
	deps, err := resolve.Dependents(st, "csrv", "PW")
	if err != nil {
		t.Fatal(err)
	}
	toPush, err := fanOutSet(st, pw, deps)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range toPush {
		got = append(got, s.Project+"/"+s.Name)
	}
	if len(got) != 1 || got[0] != "drydock/DSN" {
		t.Errorf("fan-out set = %v, want just drydock/DSN — the derived secret's destination is the one holding a stale composed value", got)
	}
}

// The rotated secret's own destinations are still included, and a secret with
// no destination anywhere is not invented into the set.
func TestFanOutSetIncludesTheRotatedSecretAndSkipsUndeliveredOnes(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	if err := runDerive([]string{"--project", "q", "--name", "PLAIN", "--from", "x:{{p/TOK}}"}); err != nil {
		t.Fatal(err)
	}
	tok := mustSecret(t, st, "p", "TOK")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if _, err := m.AddGHTarget(tok.ID, "Einlanzerous/p", "TOK"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "target.add", SecretID: tok.ID,
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}
	deps, err := resolve.Dependents(st, "p", "TOK")
	if err != nil {
		t.Fatal(err)
	}
	toPush, err := fanOutSet(st, tok, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(toPush) != 1 || toPush[0].Name != "TOK" {
		t.Errorf("fan-out set = %v, want just p/TOK (q/PLAIN has no destination)", toPush)
	}
}

// SIGNET_ACTOR_ROLE decides what a hash-chained ledger records about who acted,
// so its handling has to be exact: validated before anything happens, trimmed
// the way every other signet env var is, and refused rather than downgraded.
func TestActorRoleDeclaration(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want store.ActorRole
		ok   bool
	}{
		{"absent defaults to human", "", store.RoleHuman, true},
		{"declarable role is honored", "rule_engine", store.RoleRuleEngine, true},
		{"dispatcher is declarable", "dispatcher", store.RoleDispatcher, true},
		// A trailing newline is what a heredoc or a CI variable editor produces.
		// Refusing it would be refusing a correct answer over invisible bytes.
		{"trailing newline is trimmed", "rule_engine\n", store.RoleRuleEngine, true},
		{"CR is trimmed", "rule_engine\r\n", store.RoleRuleEngine, true},
		// daemon and healer assert that signet acted on its own initiative,
		// which an env var cannot honestly claim.
		{"daemon is refused", "daemon", "", false},
		{"healer is refused", "healer", "", false},
		{"nonsense is refused", "wizard", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SIGNET_ACTOR_ROLE", tc.env)
			got, err := checkActorRole()
			if tc.ok && err != nil {
				t.Fatalf("rejected a declarable role: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("accepted a role that cannot be declared")
				}
				// The message has to name the alternatives, or the operator is
				// left guessing at a closed set.
				if !strings.Contains(err.Error(), "one of:") {
					t.Errorf("refusal does not list the declarable roles: %v", err)
				}
				return
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The declared role has to reach the chain, not just be computed.
func TestDeclaredRoleIsRecordedInTheLedger(t *testing.T) {
	st := newCLIVault(t)
	t.Setenv("SIGNET_ACTOR_ROLE", "rule_engine")
	role, err := checkActorRole()
	if err != nil {
		t.Fatal(err)
	}
	declaredRole = role
	t.Cleanup(func() { declaredRole = store.RoleHuman })

	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no audit entry")
	}
	if entries[0].ActorRole != store.RoleRuleEngine {
		t.Errorf("ledger recorded role %q, want rule_engine — an agent's write is indistinguishable from a person's",
			entries[0].ActorRole)
	}
}

// import is the other version-writer, and the provenance fix originally missed
// it: importing over a minted secret left it claiming signet had minted the
// value, so rotate would have minted over a credential from an env file.
func TestImportMarksImportedValuesAsExternallyIssued(t *testing.T) {
	st := newCLIVault(t)
	if err := runGenerate([]string{"--project", "p", "--name", "TOK"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	env := filepath.Join(dir, "p.env")
	if err := os.WriteFile(env, []byte("TOK=from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", "p", env}); err != nil {
		t.Fatal(err)
	}
	if mustSecret(t, st, "p", "TOK").Generated {
		t.Fatal("imported value still reads as signet-minted")
	}
	if err := runRotate([]string{"--secret", "p/TOK"}); err == nil {
		t.Error("rotate minted over a value that came from an env file")
	}
}
