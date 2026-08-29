package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/Einlanzerous/signet/internal/redact"
	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
)

// exitError carries a child process's exit status back to main, which exits
// with it rather than with the 1 that log.Fatal would produce.
//
// `exec` is the one verb whose exit code is not its own verdict: the caller
// asked to run a command, and a script wrapping `signet exec -- pytest` needs
// pytest's answer, not signet's opinion of it. Returned rather than
// os.Exit'd at the call site so the command stays drivable from a test, which
// is the same trade `render --check` makes with errRenderCheckBlocked.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("command exited %d", e.code) }

// secretList collects a repeatable --secret flag.
type secretList []string

func (s *secretList) String() string     { return strings.Join(*s, ",") }
func (s *secretList) Set(v string) error { *s = append(*s, v); return nil }

// runExec runs a command with secrets in its environment and never on a
// terminal.
//
// The problem it solves is not that `reveal` is inconvenient. It is that the
// invariant worth holding is "plaintext never enters the transcript", and a
// permission rule on a verb cannot express that: a rule matches the tool
// invocation, not the processes it spawns, so a script calling `signet reveal`
// internally runs unprompted while the honest direct path is refused. Gating
// the verb costs the capability without buying the guarantee.
//
// Injection into a child's environment is the shape every comparable tool
// settled on — `op run`, `aws-vault exec`, `chamber exec`, `doppler run` —
// because it is the one that lets a caller use a credential without holding it.
func runExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	project := fs.String("project", "", "inject every secret in this project, keyed by its name")
	var secrets secretList
	fs.Var(&secrets, "secret", "inject one secret as project/NAME (repeatable)")
	redactOut := fs.Bool("redact", false, "filter the child's stdout and stderr, replacing managed values with a named placeholder")
	fs.Parse(args)

	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("usage: signet exec [--project <p>] [--secret <p/NAME>] [--redact] -- <command> [args...]")
	}
	if *project == "" && len(secrets) == 0 {
		// Refused rather than defaulted to the whole vault. A command run with
		// every credential in its environment is the opposite of what this verb
		// is for, and it is not the kind of thing to arrive by omission.
		return fmt.Errorf("exec needs --project or --secret: it injects what you name, and naming nothing would either inject nothing or inject everything")
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	inject, err := a.execEnv(*project, secrets)
	if err != nil {
		return err
	}

	// Recorded before the command runs, not after. A child that hangs, is
	// killed, or takes the machine down with it has still had the values —
	// writing the ledger entry on the way out would lose exactly the disclosures
	// worth investigating.
	if err := a.auditExec(inject, argv[0], *redactOut); err != nil {
		return err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = mergeEnv(os.Environ(), inject)
	cmd.Stdin = os.Stdin

	var closers []io.Closer
	if *redactOut {
		filter, err := a.redactionFilter()
		if err != nil {
			return err
		}
		// To stderr, and before the child starts: it is a statement about what
		// the operator is about to read, and on stdout it would corrupt the
		// output of anything being piped.
		fmt.Fprintf(os.Stderr, "signet: %s\n", filter.Summary())
		outW := filter.Writer(os.Stdout)
		errW := filter.Writer(os.Stderr)
		cmd.Stdout, cmd.Stderr = outW, errW
		closers = append(closers, outW, errW)
	} else {
		// Handed the real files rather than a pipe, so the child keeps whatever
		// terminal it was given: progress bars, colour, and anything that asks
		// isatty. --redact necessarily gives that up, which is a reason to make
		// it a flag rather than the default.
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}

	// Forwarded rather than inherited. The child is in signet's process group,
	// so a Ctrl-C at a terminal reaches it anyway — but a SIGTERM sent to signet
	// alone (a supervisor, a timeout, a CI cancel) would otherwise kill the
	// wrapper and orphan the command that holds the credentials.
	stop := forwardSignals(cmd)
	waitErr := cmd.Wait()
	stop()

	// Flushed before the exit status is considered: the filter holds back the
	// tail of the stream, and returning early would drop the child's last line
	// — which on a failure is usually the one that says why.
	for _, c := range closers {
		if err := c.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "signet: could not flush redacted output: %v\n", err)
		}
	}

	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return &exitError{code: exitStatus(ee)}
	}
	return waitErr
}

// exitStatus reduces a child's wait status to the number a shell would report.
//
// ExitCode returns -1 when the child died on a signal, and os.Exit(-1) becomes
// 255 — a generic failure, indistinguishable from the command itself deciding
// to fail. That collapses exactly the case this command deliberately creates:
// forwardSignals exists so a CI cancel or a Ctrl-C reaches the child, and when
// it works the child dies on a signal. Reporting 255 there would make the
// README's "the child's exit code is signet's exit code" false in precisely the
// case the sentence two lines below it describes.
//
// 128+N is the convention every shell uses, so `signet exec -- …` cancelled
// with SIGTERM answers 143 the way the same command answers 143 without the
// wrapper.
func exitStatus(ee *exec.ExitError) int {
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}

// execEnv resolves what the selectors name, keyed by the environment variable
// each will become.
//
// A secret that cannot be resolved is an error, never an omission. The child
// would otherwise start with the variable unset and read it as empty, which is
// how a half-configured process authenticates against nothing and reports a
// failure that names the wrong cause.
func (a *app) execEnv(project string, refs []string) (map[string]injected, error) {
	out := map[string]injected{}
	if project != "" {
		secrets, err := a.st.ListSecrets()
		if err != nil {
			return nil, err
		}
		found := false
		for i := range secrets {
			sec := secrets[i]
			if sec.Project != project {
				continue
			}
			found = true
			r, err := resolve.Current(a.st, a.key, &sec)
			if errors.Is(err, resolve.ErrNoVersion) {
				// Registered but never given a value: absent rather than
				// broken, and the state every secret passes through. Injecting
				// it empty is the failure this function exists to avoid.
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("%s/%s cannot be resolved: %w", project, sec.Name, err)
			}
			out[sec.Name] = injected{secret: sec, value: r.Value}
		}
		if !found {
			return nil, fmt.Errorf("project %s has no secrets", project)
		}
	}
	for _, ref := range refs {
		p, name, err := parseSecretRef(ref)
		if err != nil {
			return nil, err
		}
		sec, err := a.st.GetSecret(p, name)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, fmt.Errorf("no secret %s/%s", p, name)
		}
		r, err := resolve.Current(a.st, a.key, sec)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be resolved: %w", ref, err)
		}
		// When both selectors name the same key, the explicit one wins: it is
		// the more specific instruction, and the only way to run a project's
		// environment with a single value taken from somewhere else.
		out[name] = injected{secret: *sec, value: r.Value}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nothing to inject: the selectors matched no secret with a value")
	}
	return out, nil
}

// injected is one resolved secret bound for the child's environment.
type injected struct {
	secret store.Secret
	value  string
}

// mergeEnv overlays the injected values on the inherited environment.
//
// Injected wins. The point of the verb is that the child runs with what the
// vault holds, and an inherited variable of the same name is exactly the stale
// copy signet exists to replace — silently deferring to it would make the
// command behave differently depending on the caller's shell.
func mergeEnv(base []string, inject map[string]injected) []string {
	skip := map[string]bool{}
	for k := range inject {
		skip[k] = true
	}
	out := make([]string, 0, len(base)+len(inject))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && skip[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	for _, k := range sortedInjected(inject) {
		out = append(out, k+"="+inject[k].value)
	}
	return out
}

func sortedInjected(m map[string]injected) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// redactionFilter builds the filter over every value the vault can currently
// resolve — not merely the injected ones.
//
// The wider set is the whole point of the feature. A command that reads a
// credential from a file signet also manages, or that prints an unrelated
// variable from an inherited environment, leaks a value signet knows perfectly
// well; matching only what this invocation injected would let it through while
// reporting that the stream was filtered.
//
// Unresolvable secrets are skipped rather than fatal. A broken derivation is a
// value that cannot appear in the output either, so it costs nothing to omit —
// and refusing to run a command because some unrelated entry is broken would
// make the safer flag the one that fails more often.
func (a *app) redactionFilter() (*redact.Filter, error) {
	secrets, err := a.st.ListSecrets()
	if err != nil {
		return nil, err
	}
	var values []redact.Value
	for i := range secrets {
		sec := secrets[i]
		r, err := resolve.Current(a.st, a.key, &sec)
		if err != nil {
			continue
		}
		values = append(values, redact.Value{Name: sec.Project + "/" + sec.Name, Plain: r.Value})
	}
	return redact.New(values), nil
}

// auditExec records the disclosure, one entry per secret.
//
// Per secret rather than one entry for the run, because the question the ledger
// has to answer is "who has seen this credential", and it is asked from the
// credential's side — `signet audit --secret csrv/TOKEN`. A single entry naming
// a project would leave that query empty for every secret the project holds.
//
// It reuses KindSecretReveal rather than introducing a kind of its own: an
// investigator asking what disclosed a value wants both channels in one answer,
// and a separate kind would silently halve the result of every existing query.
func (a *app) auditExec(inject map[string]injected, command string, redacted bool) error {
	note := ""
	if redacted {
		note = ", output redacted"
	}
	for _, name := range sortedInjected(inject) {
		in := inject[name]
		if _, err := a.st.AppendAudit(store.AuditRecord{
			Actor: cliActor(), Action: "secret.exec", SecretID: in.secret.ID,
			Details: fmt.Sprintf("injected %s/%s into the environment of %q%s",
				in.secret.Project, in.secret.Name, command, note),
			EventKind: store.KindSecretReveal, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}); err != nil {
			return err
		}
		// A derived secret's value carries its inputs', so injecting it
		// discloses them too — see auditDerivedInputs for why the traversal
		// lives there rather than here.
		if err := a.auditDerivedInputs(&in.secret, store.AuditRecord{
			Action: "secret.exec",
			Details: fmt.Sprintf("value disclosed to %q via exec of %s/%s, which derives from it",
				command, in.secret.Project, in.secret.Name),
		}); err != nil {
			return err
		}
	}
	return nil
}

// forwardSignals relays interrupts to the child until the returned function is
// called.
func forwardSignals(cmd *exec.Cmd) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
