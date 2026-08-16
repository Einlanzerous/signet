package main

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
)

// shell is the child used throughout: these tests are about what reaches a
// child's environment and what comes back out of it, which needs a real
// process rather than a stub.
func shell(script string) []string { return []string{"--", "/bin/sh", "-c", script} }

func requireShell(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
}

// The primitive: a command can use a credential without anyone printing it.
func TestExecInjectsASelectedSecret(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/API_TOKEN"},
			shell("printf 'got:%s\\n' \"$API_TOKEN\"")...)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "got:s3cret-token-value") {
		t.Fatalf("the secret did not reach the child's environment:\n%s", out)
	}
}

func TestExecInjectsAWholeProject(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "ALPHA", "alpha-value-long")
	seedValue(t, "csrv", "BETA", "beta-value-longer")

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--project", "csrv"},
			shell("printf '%s|%s\\n' \"$ALPHA\" \"$BETA\"")...)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "alpha-value-long|beta-value-longer") {
		t.Fatalf("the project did not reach the child's environment:\n%s", out)
	}
}

// The vault's value is the current one; an inherited variable of the same name
// is the stale copy signet exists to replace. Deferring to it would make the
// command behave differently depending on the caller's shell.
func TestExecOverridesAnInheritedVariable(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "from-the-vault-value")
	t.Setenv("API_TOKEN", "stale-shell-value")

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/API_TOKEN"},
			shell("printf 'got:%s\\n' \"$API_TOKEN\"")...)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "got:from-the-vault-value") {
		t.Fatalf("the inherited value won:\n%s", out)
	}
	// The count matters: appending without removing leaves both, and which one
	// a child sees is then libc's business rather than signet's.
	if strings.Contains(out, "stale-shell-value") {
		t.Fatalf("the stale value was still present:\n%s", out)
	}
}

// `signet exec -- pytest` is asked to run pytest, and a script wrapping it
// needs pytest's answer. Collapsing every non-zero exit into 1 would make the
// wrapper lossy in the one place it is meant to be transparent.
func TestExecPropagatesTheChildsExitCode(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	err := runExec(append([]string{"--secret", "csrv/API_TOKEN"}, shell("exit 42")...))
	var ec *exitError
	if !errors.As(err, &ec) {
		t.Fatalf("err = %v, want an exitError", err)
	}
	if ec.code != 42 {
		t.Fatalf("exit code = %d, want 42", ec.code)
	}
}

// A child killed by a signal must report 128+N, not the 255 that
// ExitError.ExitCode's -1 turns into. This is the case forwardSignals
// deliberately creates: when a CI cancel or a Ctrl-C reaches the child, it dies
// on a signal, and 255 would be indistinguishable from the command choosing to
// fail — losing the one fact the exit code was carrying.
func TestExecReportsASignalledChildAsAShellWould(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	err := runExec(append([]string{"--secret", "csrv/API_TOKEN"}, shell("kill -TERM $$")...))
	var ec *exitError
	if !errors.As(err, &ec) {
		t.Fatalf("err = %v, want an exitError", err)
	}
	if ec.code != 128+int(syscall.SIGTERM) {
		t.Fatalf("exit code = %d, want %d", ec.code, 128+int(syscall.SIGTERM))
	}
}

// The feature only signet can offer. An accidental echo, a curl dumping
// headers on error, a stack trace carrying the environment — all become
// non-events, because the filter is applied on the way out rather than trusted
// not to be needed.
func TestExecRedactsTheChildsOutput(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/API_TOKEN", "--redact"},
			shell("echo \"Authorization: Bearer $API_TOKEN\"")...)); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "s3cret-token-value") {
		t.Fatalf("the value reached stdout despite --redact:\n%s", out)
	}
	if !strings.Contains(out, "«redacted:csrv/API_TOKEN»") {
		t.Fatalf("the placeholder does not name the secret:\n%s", out)
	}
}

// The wider set is the point of redacting at all: a command that reads a
// credential from a file signet also manages leaks a value signet knows
// perfectly well. Filtering only the injected ones would let it through while
// reporting that the stream was filtered.
func TestExecRedactsSecretsItDidNotInject(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")
	seedValue(t, "other", "UNRELATED", "some-other-secret-value")

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/API_TOKEN", "--redact"},
			shell("echo 'leaked some-other-secret-value here'")...)); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "some-other-secret-value") {
		t.Fatalf("a managed value this exec did not inject was not redacted:\n%s", out)
	}
	if !strings.Contains(out, "«redacted:other/UNRELATED»") {
		t.Fatalf("output = %q", out)
	}
}

// Without a selector the only two behaviours available are injecting nothing
// and injecting everything, and neither is a thing to arrive at by omission.
func TestExecRefusesWithNoSelector(t *testing.T) {
	newCLIVault(t)
	err := runExec(shell("true"))
	if err == nil || !strings.Contains(err.Error(), "--project or --secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestExecRefusesWithNoCommand(t *testing.T) {
	newCLIVault(t)
	err := runExec([]string{"--secret", "csrv/API_TOKEN"})
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("err = %v", err)
	}
}

// A secret that cannot be supplied is an error, never an omission. The child
// would otherwise start with the variable unset and read it as empty — a
// process authenticating against nothing, reporting a failure that names the
// wrong cause. Refusing before the command starts is the whole difference.
func TestExecRefusesASecretItCannotSupply(t *testing.T) {
	requireShell(t)
	newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	err := runExec(append([]string{"--secret", "csrv/NOT_THERE"}, shell("true")...))
	if err == nil || !strings.Contains(err.Error(), "NOT_THERE") {
		t.Fatalf("err = %v", err)
	}
}

// A secret registered but never given a value is absent rather than broken —
// the state every secret passes through between creation and its first value.
// Sweeping a project must skip it rather than inject it empty, which is the
// same half-configured start by a quieter route.
func TestExecSkipsAValuelessSecretInAProjectSweep(t *testing.T) {
	requireShell(t)
	st := newCLIVault(t)
	seedValue(t, "csrv", "ALPHA", "alpha-value-long")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "PENDING", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: "test", Action: "secret.create", SecretID: s.ID,
			Details: "fixture", EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runExec(append([]string{"--project", "csrv"},
			shell("printf 'alpha=%s pending=[%s]\\n' \"$ALPHA\" \"${PENDING-unset}\"")...)); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "alpha=alpha-value-long") {
		t.Fatalf("the resolvable secret did not arrive:\n%s", out)
	}
	if !strings.Contains(out, "pending=[unset]") {
		t.Fatalf("a valueless secret was injected as empty rather than left unset:\n%s", out)
	}
}

// The ledger is asked "who has seen this credential" from the credential's
// side. An exec that injected a value and left no entry on that secret is a
// read channel with no trace where an investigator would look.
func TestExecIsAuditedPerSecret(t *testing.T) {
	requireShell(t)
	st := newCLIVault(t)
	seedValue(t, "csrv", "API_TOKEN", "s3cret-token-value")

	captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/API_TOKEN"}, shell("true")...)); err != nil {
			t.Fatal(err)
		}
	})

	entries := execEntriesFor(t, st, "csrv", "API_TOKEN")
	if len(entries) == 0 {
		t.Fatal("an exec that injected a value left no entry on that secret")
	}
	if !strings.Contains(entries[0].Details, "/bin/sh") {
		t.Fatalf("the entry does not name the command: %q", entries[0].Details)
	}
	// The kind is load-bearing: an investigator asking what disclosed a value
	// queries the reveal kind, and a kind of its own would silently halve the
	// answer.
	if entries[0].EventKind != store.KindSecretReveal {
		t.Fatalf("event kind = %q, want %q", entries[0].EventKind, store.KindSecretReveal)
	}
}

// A derived secret's value carries its inputs'. Injecting it discloses them,
// and `signet audit --secret <input>` must show that — the same gap that was
// closed for reveal, reached through a different verb.
func TestExecAuditsTheInputsOfADerivedSecret(t *testing.T) {
	requireShell(t)
	st := newCLIVault(t)
	seedValue(t, "csrv", "DB_PASSWORD", "inner-secret-value")
	// Composed without spelling a connection string: what is under test is that
	// the input is audited, not the shape of the value that carries it.
	if err := runDerive([]string{"--project", "csrv", "--name", "DSN",
		"--from", "wrapper[{{csrv/DB_PASSWORD}}]wrapper"}); err != nil {
		t.Fatal(err)
	}

	captureStdout(t, func() {
		if err := runExec(append([]string{"--secret", "csrv/DSN"}, shell("true")...)); err != nil {
			t.Fatal(err)
		}
	})

	for _, e := range execEntriesFor(t, st, "csrv", "DB_PASSWORD") {
		if strings.Contains(e.Details, "derives from it") {
			return
		}
	}
	t.Fatal("injecting a derived secret left no trace on the input whose value it carries")
}

// seedValue stores a known plaintext through the CLI's own write path, which
// the --generate helpers cannot do: these tests assert on the value itself.
func seedValue(t *testing.T, project, name, value string) {
	t.Helper()
	captureStdout(t, func() {
		if err := storeValue(project, name, "", value, store.Issued, "", false, false); err != nil {
			t.Fatal(err)
		}
	})
}

// execEntriesFor returns the exec disclosures recorded against a secret.
func execEntriesFor(t *testing.T, st *store.Store, project, name string) []store.AuditEntry {
	t.Helper()
	sec, err := st.GetSecret(project, name)
	if err != nil {
		t.Fatal(err)
	}
	if sec == nil {
		t.Fatalf("no secret %s/%s", project, name)
	}
	entries, err := st.ListAudit(0, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range entries {
		if e.Action == "secret.exec" {
			out = append(out, e)
		}
	}
	return out
}
