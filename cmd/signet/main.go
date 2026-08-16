// Command signet is the construct-server credential vault and outbound-sync
// control plane (IDEA-13, first slice): a host-resident single static binary
// that is both a CLI and a thin HTTP API.
//
//	signet init                                    # create master key + database
//	signet import --project lyceum ~/projects/lyceum/.env
//	signet generate --project csrv --name API_TOKEN     # signet mints the value
//	signet set --project csrv --name API_TOKEN          # value on stdin
//	signet rotate --secret csrv/API_TOKEN [--expires D] # new value + fan-out
//	signet derive --project drydock --name DSN --from 'u:{{csrv/PW}}@h'
//	signet reveal --project csrv --name API_TOKEN  # audited
//	signet render --project lyceum [--check] [--prune]  # write / drift-check file targets
//	signet target list [--secret csrv/NAME] [--project csrv]
//	signet target add --secret csrv/RELEASE_BOT_PRIVATE_KEY --gh-repo Einlanzerous/purser
//	signet target add-key --project csrv --path ~/construct-server/.env --name API_TOKEN
//	signet target rm  --secret csrv/RELEASE_BOT_PRIVATE_KEY --gh-repo Einlanzerous/purser
//	signet sync [--secret csrv/RELEASE_BOT_PRIVATE_KEY] [--check]
//	signet status
//	signet audit [--secret csrv/NAME] [--verify]
//	signet serve                                   # HTTP API for the Switchyard mirror
//	signet version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Einlanzerous/signet/internal/api"
	"github.com/Einlanzerous/signet/internal/config"
	"github.com/Einlanzerous/signet/internal/derive"
	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/ops"
	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
	"github.com/Einlanzerous/signet/internal/vault"
	"github.com/Einlanzerous/signet/internal/version"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("signet: ")

	cmd := "help"
	args := os.Args[1:]
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}

	// Before any command runs: a role that cannot be declared must fail while
	// nothing has happened yet, not when the first audit record is built —
	// which on `init` would be after the master key and database exist.
	role, err := checkActorRole()
	if err != nil {
		log.Fatal(err)
	}
	declaredRole = role

	switch cmd {
	case "init":
		err = runInit()
	case "import":
		err = runImport(args)
	case "set":
		err = runSet(args)
	case "reveal":
		err = runReveal(args)
	case "render":
		err = runRender(args)
	case "target":
		err = runTarget(args)
	case "generate":
		err = runGenerate(args)
	case "rotate":
		err = runRotate(args)
	case "derive":
		err = runDerive(args)
	case "sync":
		err = runSync(args)
	case "status":
		err = runStatus(args)
	case "audit":
		err = runAudit(args)
	case "serve":
		err = runServe()
	case "version":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "signet: unknown command %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "commands: init, import, set, generate, rotate, derive, reveal, render, target, sync, status, audit, serve, version")
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

// cliActor identifies the invoking human in audit entries.
func cliActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}

// cliRole is the role the CLI's ledger entries are attributed to.
//
// It defaults to human because that is what the CLI usually is, and reads
// SIGNET_ACTOR_ROLE so automation can say otherwise. Several verbs are
// deliberately allowlisted for agents (`generate`, `rotate`, `derive`, `sync`,
// `target`), and recording those as human makes an agent-driven change
// indistinguishable from a person's in a log whose whole purpose is saying who
// did what — permanently, since the field is covered by the chain hash.
//
// The value is validated once at startup, not here. Validating lazily meant an
// unusable value aborted the process at the moment an audit record was built —
// which on `signet init` is after the master key and database have been written,
// leaving a vault that is unaudited and cannot be re-inited. A bad env var must
// fail before anything happens, not partway through.
func cliRole() store.ActorRole { return declaredRole }

// declaredRole is resolved by checkActorRole before any command runs.
var declaredRole = store.RoleHuman

// checkActorRole validates SIGNET_ACTOR_ROLE and returns the role to attribute
// CLI writes to.
//
// Only declarable roles are honored, and the check is the same one the API's
// header goes through: `daemon` and `healer` mean "signet acted on its own
// initiative", which an env var cannot honestly assert. An unrecognized value
// is refused rather than silently downgraded to human, because a caller that
// meant to declare something and was ignored is exactly the case that would
// write the wrong answer into an append-only ledger.
func checkActorRole() (store.ActorRole, error) {
	// Through config.EnvOr, so this gets the whitespace trimming every other
	// signet env var gets: a value with a trailing newline — which is what a
	// shell heredoc or a CI variable editor produces — is the same declaration,
	// and refusing it would be refusing a correct answer over invisible bytes.
	raw := config.EnvOr("SIGNET_ACTOR_ROLE", "")
	if raw == "" {
		return store.RoleHuman, nil
	}
	role := store.ActorRole(raw)
	if !store.DeclarableActorRole(role) {
		return "", fmt.Errorf("SIGNET_ACTOR_ROLE=%q cannot be declared (one of: %s)",
			raw, strings.Join(store.DeclarableActorRoles(), ", "))
	}
	return role, nil
}

// app bundles the wired-up dependencies shared by subcommands.
type app struct {
	cfg config.Config
	st  *store.Store
	key []byte
}

func setup() (*app, error) {
	cfg := config.Load()
	key, err := vault.LoadKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w (run `signet init` first?)", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	return &app{cfg: cfg, st: st, key: key}, nil
}

func (a *app) close() { a.st.Close() }

// parseSecretRef splits "project/NAME".
func parseSecretRef(ref string) (project, name string, err error) {
	i := strings.Index(ref, "/")
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("secret ref must be project/NAME, got %q", ref)
	}
	return ref[:i], ref[i+1:], nil
}

// ---- init -------------------------------------------------------------------

func runInit() error {
	cfg := config.Load()
	if _, err := os.Stat(cfg.MasterKeyFile); err == nil {
		return fmt.Errorf("master key already exists at %s", cfg.MasterKeyFile)
	}
	key, err := vault.GenerateKey()
	if err != nil {
		return err
	}
	if err := vault.WriteKeyFile(cfg.MasterKeyFile, key); err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.AppendAudit(store.AuditRecord{
		Actor: cliActor(), Action: "vault.init", Details: "master key + database created",
		EventKind: store.KindVaultInit, ActorRole: cliRole(),
		Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
	}); err != nil {
		return err
	}
	fmt.Printf("initialized vault\n  key: %s (0400)\n  db:  %s\n", cfg.MasterKeyFile, cfg.DBPath)
	fmt.Println("back the key file up somewhere safe — without it the vault is unreadable")
	return nil
}

// ---- import -----------------------------------------------------------------

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	project := fs.String("project", "", "project the env file belongs to (required)")
	scope := fs.String("scope", "", "scope recorded on newly created secrets")
	fs.Parse(args)
	if *project == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: signet import --project <p> <path/to/.env>")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	res, err := ops.ImportEnv(a.st, a.key, *project, *scope, path, cliActor(), cliRole())
	if err != nil {
		return err
	}
	fmt.Printf("imported %s → project %s: %d created, %d updated, %d unchanged (%d keys)\n",
		path, *project, res.Created, res.Updated, res.Unchanged, len(res.Keys))
	if len(res.Skipped) > 0 {
		fmt.Printf("%d derived, left alone: %s\n", len(res.Skipped), strings.Join(res.Skipped, ", "))
		fmt.Println("  their values are composed from other secrets; importing would have stored a copy that can drift")
	}
	fmt.Printf("file target registered: %s\n", path)
	return nil
}

// ---- set --------------------------------------------------------------------

// runGenerate mints a value and stores it, as `set --generate` does.
//
// It exists as its own verb because the permission allowlist can gate verbs and
// cannot gate flags. `Bash(signet set --generate:*)` is a prefix match, so it
// covers `signet set --generate --project p --name N` and misses the same
// command with the flag written last — a rule whose correctness depends on
// argument order is not a rule. Generating and setting are also genuinely
// different operations: this one mints a value signet already holds, while
// `set` carries plaintext in from outside, and only one of those is safe to
// hand an agent. Splitting them lets the allowlist say exactly that (SGNT-25).
func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	name := fs.String("name", "", "secret name (required)")
	scope := fs.String("scope", "", "scope")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD")
	replace := fs.Bool("replace", false, "overwrite an existing value")
	fs.Parse(args)
	if *project == "" || *name == "" {
		return fmt.Errorf("usage: signet generate --project <p> --name <N> [--scope s] [--expires YYYY-MM-DD] [--replace]")
	}
	expiresAt, expiresGiven, err := parseExpiry(fs, *expires)
	if err != nil {
		return err
	}
	value, err := vault.RandomToken(32)
	if err != nil {
		return err
	}
	return storeValue(*project, *name, *scope, value, store.Minted, expiresAt, expiresGiven, *replace)
}

// parseExpiry converts --expires and reports whether the flag was given at all,
// which is not the same question as whether it carries a date: absent means
// "leave the expiry alone", and an explicit --expires "" means "clear it",
// matching the API's set-expiry.
func parseExpiry(fs *flag.FlagSet, expires string) (string, bool, error) {
	expiresAt := ""
	if expires != "" {
		t, err := time.Parse("2006-01-02", expires)
		if err != nil {
			return "", false, fmt.Errorf("--expires: %w", err)
		}
		expiresAt = t.UTC().Format(time.RFC3339)
	}
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expires" {
			given = true
		}
	})
	return expiresAt, given, nil
}

func runSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	name := fs.String("name", "", "secret name (required)")
	scope := fs.String("scope", "", "scope")
	generate := fs.Bool("generate", false, "generate a random 32-char value instead of reading stdin (alias for `signet generate`)")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD")
	replace := fs.Bool("replace", false, "overwrite an existing minted value (only meaningful with --generate)")
	fs.Parse(args)
	if *project == "" || *name == "" {
		return fmt.Errorf("usage: signet set --project <p> --name <N> [--scope s] [--generate] [--expires YYYY-MM-DD]")
	}
	expiresAt, expiresGiven, err := parseExpiry(fs, *expires)
	if err != nil {
		return err
	}

	prov := store.Issued
	var value string
	if *generate {
		prov = store.Minted
		v, err := vault.RandomToken(32)
		if err != nil {
			return err
		}
		value = v
	} else {
		fmt.Fprintln(os.Stderr, "reading secret value from stdin (end with EOF)…")
		raw, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return err
		}
		value = strings.TrimRight(string(raw), "\n")
		if value == "" {
			return fmt.Errorf("empty value")
		}
	}
	return storeValue(*project, *name, *scope, value, prov, expiresAt, expiresGiven, *replace)
}

// storeValue is the write `set`, `generate` and `set --generate` share.
//
// prov travels with the value into AddVersion, which owns the provenance column
// — see there for why it cannot be a separate call.
func storeValue(project, name, scope, value string, prov store.Provenance, expiresAt string, expiresGiven bool, replace bool) error {
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	sec, err := a.st.GetSecret(project, name)
	if err != nil {
		return err
	}
	// The core invariant of a derived secret: it has no independently settable
	// value. Allowing this would recreate the exact bug the feature exists to
	// remove — a stored copy that can drift from the inputs it was composed
	// from, with `render --check` reporting both in sync because each matches
	// what the vault holds.
	if sec != nil && sec.Derived() {
		return fmt.Errorf("%s/%s is derived from %s — it has no value of its own to set.\n"+
			"Set one of its inputs instead, or `signet derive --from` to change how it is composed",
			project, name, sec.Derivation)
	}
	nonce, ct, err := vault.Encrypt(a.key, []byte(value))
	if err != nil {
		return err
	}

	// Anything composed from this secret changes the moment this write lands,
	// and is rewritten by the next render. Read before the write so a failure
	// here cannot strand a committed value with an unreported blast radius.
	dependents, err := resolve.Dependents(a.st, project, name)
	if err != nil {
		return err
	}

	expiryNote := ""
	v, _, err := store.MutateValue(a.st, func(m *store.Mutation) (*store.Version, store.AuditRecord, error) {
		target, action, outcome := sec, "secret.update", store.OutcomeUpdated
		if target == nil {
			created, err := m.CreateSecret(project, name, scope, bool(prov), expiresAt)
			if err != nil {
				return nil, store.AuditRecord{}, err
			}
			target, action, outcome = created, "secret.create", store.OutcomeCreated
		} else {
			// Re-read inside the transaction. Both gates below turn on facts a
			// concurrent writer can change — whether a value exists, and whether
			// signet minted it — so checking a pre-transaction snapshot would
			// make them advisory. The same reasoning as rotate's.
			fresh, err := m.GetSecretForUpdate(target.ID)
			if err != nil {
				return nil, store.AuditRecord{}, err
			}
			if fresh == nil {
				return nil, store.AuditRecord{}, fmt.Errorf("%s/%s disappeared during the write", project, name)
			}
			if fresh.Derived() {
				return nil, store.AuditRecord{}, fmt.Errorf(
					"%s/%s became derived while this ran — it has no value of its own to set", project, name)
			}
			if err := guardMintOverwrite(m, fresh, prov, replace); err != nil {
				return nil, store.AuditRecord{}, err
			}
			// On an existing secret the expiry is a second change riding along
			// with the value; it used to be parsed and dropped, so `set
			// --expires` moved the value and left the old date describing a
			// version it had replaced.
			if expiresGiven && expiresAt != fresh.ExpiresAt {
				if err := m.SetExpiry(target.ID, expiresAt); err != nil {
					return nil, store.AuditRecord{}, err
				}
				expiryNote = " · expiry cleared"
				if expiresAt != "" {
					expiryNote = " · expiry set to " + expiresAt[:10]
				}
			}
		}
		ver, err := m.AddVersion(target.ID, nonce, ct, vault.VersionHash(nonce, ct), cliActor(), prov)
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		// One entry, because it was one transaction. The version write is the
		// event; the expiry rides in its details rather than becoming a second
		// entry that could only ever be appended after the first had committed.
		return ver, store.AuditRecord{
			Actor: cliActor(), Action: action, SecretID: target.ID,
			Details:   fmt.Sprintf("%s/%s · version %d #%s%s · %s", project, name, ver.VersionNo, ver.VHash, expiryNote, provenanceWord(prov)),
			EventKind: store.KindSecretWrite, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s → version %d #%s%s\n", project, name, v.VersionNo, v.VHash, expiryNote)
	reportDependents(dependents, project, name)
	warnUndelivered(a, project, name)
	warnStaleDestinations(a, project, name, dependents)
	return nil
}

// guardMintOverwrite refuses to mint over a value that already exists.
//
// It lives here rather than in `generate` because `set --generate` performs the
// identical mint-and-overwrite, and a guard on one verb that the other walks
// around is not a guard. Minting is the case that needs it: the replaced value
// is gone and nobody ever saw the new one, so an accidental `generate` over a
// live PAT is unrecoverable in a way an accidental `set` — where the operator
// supplied the value — is not.
//
// Runs inside the caller's transaction, so the existence check and the write it
// gates cannot be separated by another writer.
func guardMintOverwrite(m *store.Mutation, fresh *store.Secret, prov store.Provenance, replace bool) error {
	if prov != store.Minted || replace {
		return nil
	}
	cur, err := m.CurrentVersionForUpdate(fresh.ID)
	if err != nil {
		return err
	}
	if cur == nil {
		// Registered but never written — nothing to lose, and the ordinary way
		// `target add-key` and `generate` are used together.
		return nil
	}
	if fresh.Generated {
		return fmt.Errorf("%s/%s already holds a value signet minted.\n"+
			"Use `signet rotate --secret %s/%s` to replace it and push the new value to its destinations, "+
			"or --replace to overwrite without fanning out",
			fresh.Project, fresh.Name, fresh.Project, fresh.Name)
	}
	return fmt.Errorf("%s/%s already holds an externally-issued value, which minting over would discard "+
		"while it is still live at the issuer.\nRe-run with --replace if that is what you mean",
		fresh.Project, fresh.Name)
}

// dateOf renders an RFC3339 timestamp as the date an operator typed, and
// returns whatever it was given when that is not possible. Values read back
// from the database have no guaranteed shape, and a display helper is not the
// place to panic over one.
func dateOf(ts string) string {
	if len(ts) < 10 {
		return ts
	}
	return ts[:10]
}

// provenanceWord is how the ledger names where a value came from.
func provenanceWord(prov store.Provenance) string {
	if prov == store.Minted {
		return "signet-minted"
	}
	return "externally issued"
}

// warnStaleDestinations reports GitHub destinations still holding the previous
// value after a write that does not push.
//
// `set` and `generate` change the vault and nothing else — only `sync` and
// `rotate` deliver. That is fine when nothing is attached, and silently wrong
// when something is: the destination now serves a value the vault has replaced,
// and the command exited 0. `--replace` made this reachable by design, and the
// refusal it satisfies advertises the path, so the warning belongs on the way
// out of every such write rather than in the one verb that prompted it.
func warnStaleDestinations(a *app, project, name string, dependents []store.Secret) {
	sec, err := a.st.GetSecret(project, name)
	if err != nil || sec == nil {
		return
	}
	toPush, err := fanOutSet(a.st, sec, dependents)
	if err != nil {
		return
	}
	// A secret carried only inside a rendered blob has no gh-actions target of
	// its own, so fanOutSet answers no about it — and the one warning that
	// tells an operator a destination still holds the previous value would stay
	// silent about the destination whose value can least be checked by hand.
	covered, _, err := renderCoverage(a.st, append([]store.Secret{*sec}, dependents...))
	if err != nil {
		return
	}
	toPush = mergeSecrets(toPush, covered)
	if len(toPush) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %d GitHub destination(s) still hold the previous value\n", len(toPush))
	for _, s := range toPush {
		fmt.Fprintf(os.Stderr, "  %s/%s\n", s.Project, s.Name)
	}
	// `sync --secret` delivers a rendered target that carries the secret as
	// well as the secret's own destinations, so one command covers both.
	fmt.Fprintln(os.Stderr, "  push them with: "+syncCommandFor(toPush))
}

// syncCommandFor names the command that pushes exactly these secrets — one
// --secret run each, because `signet sync` with no filter pushes the whole
// vault and telling an operator to do that to fix one write is wrong.
func syncCommandFor(secs []store.Secret) string {
	parts := make([]string, len(secs))
	for i, s := range secs {
		parts[i] = fmt.Sprintf("signet sync --secret %s/%s", s.Project, s.Name)
	}
	return strings.Join(parts, " && ")
}

// reportDependents names every derived secret this write just changed.
//
// It reports rather than asks. The write is already committed by the time this
// runs, which is the honest ordering: the derived values changed at the same
// instant, because they are not stored — there is no window in which the
// operator could have been asked to confirm one but not the other. What is
// actionable is knowing which renders to run next, and that is what this says.
func reportDependents(dependents []store.Secret, project, name string) {
	if len(dependents) == 0 {
		return
	}
	fmt.Printf("%d derived secret(s) now resolve differently:\n", len(dependents))
	for _, d := range dependents {
		fmt.Printf("  %s/%s — %s\n", d.Project, d.Name, d.Derivation)
	}
	fmt.Println("run `signet render` for their projects to write the new values")
}

// warnUndelivered reports a value that landed in the vault but that nothing
// delivers, so no destination will ever receive it.
//
// "the vault has it" and "render writes it" are separate facts: set records the
// value, and only import or `target add-key` records that a file wants it.
// Nothing puts the two side by side, so the gap stays invisible until someone
// happens to run `render --check` — which is how a key can be fully present in
// signet and still be missing from the file it was set for.
//
// A secret with a gh-actions target is delivered, just not to a file, so it is
// not warned about: telling someone to add-key a repo credential into an env
// file would talk them into writing a secret somewhere it was never meant to go.
//
// It stays quiet when a lookup fails: the value is already written, and a
// warning that could not be computed is not worth failing a successful set over.
func warnUndelivered(a *app, project, name string) {
	targets, err := a.st.FileTargetsForProject(project)
	if err != nil {
		return
	}
	renderTargets, err := a.st.RenderTargetsForProject(project)
	if err != nil {
		return
	}
	if len(targets) == 0 && len(renderTargets) == 0 {
		return // nothing renders this project — nothing to be wrong about
	}
	sec, err := a.st.GetSecret(project, name)
	if err != nil || sec == nil {
		return
	}
	gh, err := a.st.TargetsForSecret(sec.ID)
	if err != nil || len(gh) > 0 {
		return // delivered somewhere, so silence is the honest answer
	}
	var paths []string
	for _, t := range targets {
		cfg, err := t.FileConfig()
		if err != nil {
			return
		}
		if cfg.Manages(name) {
			return
		}
		paths = append(paths, cfg.Path)
	}
	// A rendered target delivers the value as surely as a file does, so one
	// carrying this key means it is not undelivered and there is nothing to
	// warn about.
	var rendered []string
	for _, t := range renderTargets {
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return
		}
		if cfg.Manages(name) {
			return
		}
		rendered = append(rendered, cfg.SecretName)
	}

	var dests []string
	if len(paths) > 0 {
		dests = append(dests, strings.Join(paths, ", "))
	}
	for _, r := range rendered {
		dests = append(dests, "the "+r+" render")
	}
	fmt.Fprintf(os.Stderr, "warning: nothing in %s manages %s — it will not reach %s\n",
		project, name, strings.Join(dests, " or "))
	// The suggested fix names whichever destination exists, file first: it is
	// the one whose key set is usually the source the render was seeded from.
	if len(paths) > 0 {
		fmt.Fprintf(os.Stderr, "  add it with: signet target add-key --project %s --path %s --name %s\n",
			project, paths[0], name)
		return
	}
	fmt.Fprintf(os.Stderr, "  add it with: signet target add-key --project %s --gh-secret %s --name %s\n",
		project, rendered[0], name)
}

// ---- reveal -----------------------------------------------------------------

func runReveal(args []string) error {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	name := fs.String("name", "", "secret name (required)")
	fs.Parse(args)
	if *project == "" || *name == "" {
		return fmt.Errorf("usage: signet reveal --project <p> --name <N>")
	}
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	sec, err := a.st.GetSecret(*project, *name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret %s/%s", *project, *name)
	}
	r, err := resolve.Current(a.st, a.key, sec)
	if err != nil {
		return err
	}
	plain := r.Value

	// What the ledger records has to distinguish the two cases. A derived
	// secret has no version to cite, and an entry naming one would be a
	// fiction; what it has instead is a provenance — the template — and that
	// is the thing someone auditing the reveal needs in order to explain where
	// the value came from.
	details := ""
	if sec.Derived() {
		details = fmt.Sprintf("revealed %s/%s (derived: %s) to stdout", *project, *name, sec.Derivation)
	} else {
		details = fmt.Sprintf("revealed %s/%s version %d #%s to stdout", *project, *name, r.Version.VersionNo, r.Version.VHash)
	}
	if _, err := a.st.AppendAudit(store.AuditRecord{
		Actor: cliActor(), Action: "secret.reveal", SecretID: sec.ID,
		Details:   details,
		EventKind: store.KindSecretReveal, ActorRole: cliRole(),
		Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
	}); err != nil {
		return err
	}

	// Revealing a derived secret prints its inputs' plaintext, so each input's
	// own ledger has to record that its value was disclosed. Without this the
	// entry above is the only trace, and `signet audit --secret <input>` shows
	// nothing — a read channel that crosses projects and leaves no mark on the
	// credential actually exposed. The vault's premise is that plaintext leaves
	// only in audited ways; "audited" has to mean audited where someone
	// investigating that credential would look.
	inputs, err := resolve.Inputs(a.st, sec)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		if _, err := a.st.AppendAudit(store.AuditRecord{
			Actor: cliActor(), Action: "secret.reveal", SecretID: in.ID,
			Details: fmt.Sprintf("value disclosed via reveal of %s/%s, which derives from it",
				*project, *name),
			EventKind: store.KindSecretReveal, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}); err != nil {
			return err
		}
	}
	// The provenance goes to stderr so `reveal` stays pipeable: the value alone
	// is on stdout, exactly as before, and a reader piping it into a file does
	// not get an explanation baked into their credential.
	if sec.Derived() {
		fmt.Fprintf(os.Stderr, "%s/%s is derived from: %s\n", *project, *name, sec.Derivation)
	}
	fmt.Println(plain)
	return nil
}

// ---- rotate -----------------------------------------------------------------

// runRotate mints a new value for a signet-minted secret and fans it out.
//
// It existed only on the HTTP API until SGNT-25, which meant the one way to
// rotate was a bearer token on a `curl` command line — the credential handling
// SGNT-16 deliberately removed from `sync`, reintroduced for the operation most
// likely to be automated. As a verb it is allowlistable like every other, and
// nothing has to hold the API token to reach it.
//
// The *refusals* below match the API's wording deliberately: two surfaces that
// answer "may I rotate this?" differently teach an operator that the answer
// depends on which door they used. What the two do afterwards differs on
// purpose — see rotateFanOut.
func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	ref := fs.String("secret", "", "secret ref project/NAME (required)")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD for the new value (empty clears)")
	noSync := fs.Bool("no-sync", false, "rotate without pushing to GitHub destinations")
	fs.Parse(args)
	if *ref == "" {
		return fmt.Errorf("usage: signet rotate --secret <project/NAME> [--expires YYYY-MM-DD] [--no-sync]")
	}
	project, name, err := parseSecretRef(*ref)
	if err != nil {
		return err
	}
	expiresAt, expiresGiven, err := parseExpiry(fs, *expires)
	if err != nil {
		return err
	}
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	sec, err := a.st.GetSecret(project, name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret %s/%s", project, name)
	}
	if err := ops.Rotatable(sec); err != nil {
		return err
	}

	// Read before the write, not after. The derivation graph does not change
	// because a value did, so this answer is the same either side of the commit
	// — but taken afterwards, a failure here would abort the fan-out with the
	// new value already in the vault and the destinations still holding the old
	// one, which is the exact state rotation exists to avoid.
	dependents, err := resolve.Dependents(a.st, project, name)
	if err != nil {
		return err
	}

	value, err := vault.RandomToken(32)
	if err != nil {
		return err
	}
	nonce, ct, err := vault.Encrypt(a.key, []byte(value))
	if err != nil {
		return err
	}
	setExpiry := expiresGiven && expiresAt != sec.ExpiresAt
	expiryNote := ""
	switch {
	case setExpiry && expiresAt == "":
		expiryNote = " · expiry cleared"
	case setExpiry:
		expiryNote = " · expiry set to " + expiresAt[:10]
	case sec.ExpiresAt != "":
		// The value moved and the date did not. Said out loud because the
		// alternative is an expiry that now describes a version this command
		// replaced — the silent half of the bug `set --expires` was fixed for.
		//
		// dateOf rather than a slice: this string comes from the database, not
		// from the flag parser, so its length is not something this code gets
		// to assume.
		expiryNote = " · expiry unchanged (" + dateOf(sec.ExpiresAt) + ")"
	}

	v, _, err := store.MutateValue(a.st, func(m *store.Mutation) (*store.Version, store.AuditRecord, error) {
		// Re-read inside the transaction. The gates above ran against a snapshot
		// taken before it opened, and both facts they test can change: another
		// writer could have derived this secret, or replaced its minted value
		// with one from stdin, in the window between. Rechecking here is what
		// makes the refusal binding rather than advisory.
		fresh, err := m.GetSecretForUpdate(sec.ID)
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		if fresh == nil {
			return nil, store.AuditRecord{}, fmt.Errorf("%s/%s disappeared during rotation", project, name)
		}
		if err := ops.Rotatable(fresh); err != nil {
			return nil, store.AuditRecord{}, err
		}
		if setExpiry {
			if err := m.SetExpiry(sec.ID, expiresAt); err != nil {
				return nil, store.AuditRecord{}, err
			}
		}
		ver, err := m.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), cliActor(), store.Minted)
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		return ver, store.AuditRecord{
			Actor: cliActor(), Action: "rotate", SecretID: sec.ID,
			Details:   fmt.Sprintf("rotated %s/%s → version %d #%s%s", project, name, ver.VersionNo, ver.VHash, expiryNote),
			EventKind: store.KindRotation, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeRotated},
		}, nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s → version %d #%s%s\n", project, name, v.VersionNo, v.VHash, expiryNote)
	reportDependents(dependents, project, name)

	if *noSync {
		// Names every secret this rotation changed the delivered value of, not
		// just the rotated one: the derived dependents moved too, and a hint
		// that omits them leaves their destinations stale.
		toPush, ferr := fanOutSet(a.st, sec, dependents)
		switch {
		case ferr != nil || len(toPush) == 0:
			fmt.Println("not synced (--no-sync); no GitHub destinations to push")
		default:
			fmt.Println("not synced (--no-sync); push with:")
			fmt.Println("  " + syncCommandFor(toPush))
		}
		return nil
	}
	return rotateFanOut(a, sec, dependents)
}

// fanOutSet returns the secrets a rotation has to push: the rotated one, plus
// every derived secret built on it, narrowed to those with a GitHub
// destination.
func fanOutSet(st *store.Store, sec *store.Secret, dependents []store.Secret) ([]store.Secret, error) {
	return withGHTargets(st, append([]store.Secret{*sec}, dependents...))
}

// withGHTargets narrows a candidate list to the secrets that actually have a
// GitHub destination.
//
// Shared with `sync`, which needs exactly the same answer, and for exactly the
// same reason it is computed before the credential is resolved: resolving
// decrypts the vault's root credential and records a ledger entry for the read,
// so doing it for a run with nowhere to push would write down an
// authentication that never happened. PushSecret re-reads each secret's targets
// afterwards, which makes this one extra query to avoid one unnecessary
// credential read.
func withGHTargets(st *store.Store, candidates []store.Secret) ([]store.Secret, error) {
	all, err := st.ListTargets()
	if err != nil {
		return nil, err
	}
	hasGH := map[string]bool{}
	for _, t := range all {
		if t.Kind == "gh-actions" {
			hasGH[t.SecretID] = true
		}
	}
	var out []store.Secret
	for _, s := range candidates {
		if hasGH[s.ID] {
			out = append(out, s)
		}
	}
	return out, nil
}

// renderCoverage reports which of candidates a gh-render target delivers, and
// which targets those are.
//
// It is the other half of withGHTargets, and every caller that asks "does this
// value reach anywhere?" needs both. A secret carried only inside a rendered
// blob has no gh-actions target of its own, so the older question — does any
// target name this secret_id — answers no about a value that is very much
// deployed. Getting that wrong is how a rotated credential gets reported as
// having nowhere to go while the environment goes on serving the old one.
func renderCoverage(st *store.Store, candidates []store.Secret) ([]store.Secret, []store.Target, error) {
	all, err := st.RenderTargets()
	if err != nil {
		return nil, nil, err
	}
	keysOf := make([]store.GHRenderConfig, len(all))
	for i := range all {
		cfg, err := all[i].GHRenderConfig()
		if err != nil {
			return nil, nil, err
		}
		keysOf[i] = cfg
	}
	var covered []store.Secret
	var targets []store.Target
	seen := map[string]bool{}
	for _, s := range candidates {
		hit := false
		for i := range all {
			if all[i].Project != s.Project || !keysOf[i].Manages(s.Name) {
				continue
			}
			hit = true
			if !seen[all[i].ID] {
				seen[all[i].ID] = true
				targets = append(targets, all[i])
			}
		}
		if hit {
			covered = append(covered, s)
		}
	}
	return covered, targets, nil
}

// mergeSecrets appends any of extra not already in base, by id.
func mergeSecrets(base, extra []store.Secret) []store.Secret {
	have := make(map[string]bool, len(base))
	for _, s := range base {
		have[s.ID] = true
	}
	for _, s := range extra {
		if !have[s.ID] {
			have[s.ID] = true
			base = append(base, s)
		}
	}
	return base
}

// rotatable reports whether a secret may be rotated, with the API's wording.
//
// Derived is tested before Generated because a derived secret would otherwise
// fall into the externally-issued branch and be told to rotate "at the issuer"
// — advice for a value that has no issuer and no stored form.
func rotatable(sec *store.Secret) error {
	if sec.Derived() {
		return fmt.Errorf("%s/%s is derived from %s — it has no value of its own to rotate; rotate one of its inputs instead",
			sec.Project, sec.Name, sec.Derivation)
	}
	if !sec.Generated {
		return fmt.Errorf("%s/%s is externally issued — signet can fan out a new value but cannot mint one; "+
			"rotate it at the issuer, then `signet set --project %s --name %s`",
			sec.Project, sec.Name, sec.Project, sec.Name)
	}
	return nil
}

// rotateFanOut pushes the rotated secret, and every derived secret built on it,
// to their GitHub destinations.
//
// The dependents are the part worth stating. A derived secret with its own
// gh-actions target holds a value composed from the one just rotated, so it
// changed at the same instant — and pushing only the rotated secret leaves that
// destination holding a composed value built from the previous version, with
// the command exiting 0. That is the drydock DSN hazard reached through
// rotation instead of through a stale copy.
//
// A push failure exits non-zero, which is where this deliberately parts company
// with the API: there, rotation is a command whose structured result the caller
// inspects, and a fan-out error is a field on a 200 because the rotation itself
// succeeded. Here the exit code is the whole result, and a rotation whose new
// value never reached the destinations leaves the old one live where it is
// actually used — silence would report that as success.
func rotateFanOut(a *app, sec *store.Secret, dependents []store.Secret) error {
	toPush, err := fanOutSet(a.st, sec, dependents)
	if err != nil {
		return err
	}
	// A rotated secret carried inside a rendered blob has to go out with the
	// blob, or the rotation lands in the vault and the environment keeps
	// serving the credential it just replaced — silently, since the
	// destination's value can never be read back to notice.
	_, renderTargets, err := renderCoverage(a.st, append([]store.Secret{*sec}, dependents...))
	if err != nil {
		return err
	}
	if len(toPush) == 0 && len(renderTargets) == 0 {
		// Not silence: a rotated secret nothing delivers is a value that has
		// changed in the vault and nowhere else, which is worth saying plainly.
		fmt.Println("no GitHub destinations — nothing to push")
		warnUndelivered(a, sec.Project, sec.Name)
		return nil
	}

	tok, err := ops.ResolveGHToken(a.st, a.key, a.cfg.GitHubToken, cliActor(), cliRole())
	if err != nil {
		return err
	}
	noteTokenSource(tok)
	gh := syncpkg.NewGHClient(tok.Value)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pushed := 0
	var stale []store.Secret
	var renderFailed []string
	markStale := func(sec store.Secret) {
		for _, s := range stale {
			if s.ID == sec.ID {
				return
			}
		}
		stale = append(stale, sec)
	}
	for i := range toPush {
		ref := toPush[i].Project + "/" + toPush[i].Name
		results, err := syncpkg.PushSecret(ctx, a.st, a.key, gh, &toPush[i], cliActor(), cliRole())
		if err != nil {
			// A dependent whose derivation cannot resolve fails here. Reported
			// and carried past rather than returned: the rotation has already
			// committed, and abandoning the remaining destinations would leave
			// more of them holding the old value than necessary — with nothing
			// said about the ones that did succeed.
			fmt.Printf("  ✗ %s: %v\n", ref, err)
			markStale(toPush[i])
			continue
		}
		for _, r := range results {
			if r.State == "in sync" {
				pushed++
				fmt.Printf("  ✓ %s → %s (%s)\n", ref, r.Repo, r.Secret)
				// A reconciled out-of-band change is why this push was not a
				// routine fan-out; sync reports it and so must this.
				if r.Note != "" {
					fmt.Printf("    note: %s\n", r.Note)
				}
				continue
			}
			markStale(toPush[i])
			if r.Hint != "" {
				fmt.Printf("  ✗ %s → %s: %s\n", ref, r.Repo, r.Hint)
				fmt.Printf("    GitHub said: %s\n", r.Err)
			} else {
				fmt.Printf("  ✗ %s → %s: %s\n", ref, r.Repo, r.Err)
			}
		}
	}
	// The rendered blobs go last, once every secret they carry holds its new
	// value: the blob is built from current vault state, so pushing it before
	// the fan-out finished would deliver a file that is correct about the
	// rotated secret and stale about nothing — but would have to be pushed
	// again anyway if a dependent moved after it.
	for i := range renderTargets {
		t := &renderTargets[i]
		want, _, err := a.projectValues(t.Project)
		if err != nil {
			return err
		}
		res, err := syncpkg.PushRender(ctx, a.st, a.key, gh, t, want,
			syncpkg.RenderPushOptions{}, cliActor(), cliRole())
		if err != nil {
			return err
		}
		dest := res.Dest
		if res.State == "in sync" {
			pushed++
			fmt.Printf("  ✓ %s render → %s\n", t.Project, dest)
			if res.Note != "" {
				fmt.Printf("    note: %s\n", res.Note)
			}
			continue
		}
		// Tracked apart from `stale`, which names secrets and builds a
		// per-secret remediation. A rendered target is not any one secret's
		// destination, so the command that retries it is a project-wide sync.
		renderFailed = append(renderFailed, fmt.Sprintf("%s render → %s: %s", t.Project, dest, res.Err))
	}

	if len(stale) > 0 || len(renderFailed) > 0 {
		var msg strings.Builder
		fmt.Fprintf(&msg, "rotated, but %d destination(s) did not receive the new value (%d push(es) succeeded) — the old value is still live there",
			len(stale)+len(renderFailed), pushed)
		if len(stale) > 0 {
			// Names the secrets whose destinations actually failed, which are
			// not necessarily the rotated one: a derived dependent can fail on
			// its own, and a remediation command naming the rotated secret
			// would not fix it.
			fmt.Fprintf(&msg, "\n  %s", syncCommandFor(stale))
		}
		for _, f := range renderFailed {
			fmt.Fprintf(&msg, "\n  %s", f)
		}
		return errors.New(msg.String())
	}
	return nil
}

// ---- derive -----------------------------------------------------------------

func runDerive(args []string) error {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	name := fs.String("name", "", "secret name (required)")
	from := fs.String("from", "", "template, e.g. 'postgres://u:{{other/PW}}@h/db' (required)")
	scope := fs.String("scope", "", "scope, when creating")
	replace := fs.Bool("replace", false, "convert an existing stored secret, abandoning its stored value")
	clear := fs.Bool("clear", false, "stop deriving; the last stored version becomes current again")
	fs.Parse(args)
	if *project == "" || *name == "" || (*from == "" && !*clear) {
		return fmt.Errorf("usage: signet derive --project <p> --name <N> --from '<template>' [--scope s] [--replace]\n" +
			"       signet derive --project <p> --name <N> --clear\n" +
			"  {{NAME}} refers to this project; {{other-project/NAME}} crosses projects")
	}
	if *clear && *from != "" {
		return fmt.Errorf("--clear and --from are opposites; pass one")
	}

	// Parsed before the vault is opened: a malformed template should fail on
	// the spot, not after a write has been prepared.
	var tmpl derive.Template
	if !*clear {
		var err error
		tmpl, err = derive.Parse(*from)
		if err != nil {
			return err
		}
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	existing, err := a.st.GetSecret(*project, *name)
	if err != nil {
		return err
	}

	if *clear {
		return a.clearDerivation(existing, *project, *name)
	}
	// Converting a stored secret has to be asked for. Its stored value is a
	// credential that may be live somewhere signet cannot see, and replacing it
	// with a computed one on the next render is not a conversion — it is a
	// rotation nobody asked for. --replace is how the operator says they meant
	// it, which is also the shape the motivating case takes: the DSN is already
	// in the vault as a hand-composed value, and this is what un-duplicates it.
	//
	// The old versions are left in place rather than deleted. Nothing reads them
	// while the derivation stands, the ledger's history stays intact, and
	// clearing the derivation restores the last stored value — a destructive
	// conversion would be the one operation in this vault with no way back.
	if existing != nil && !existing.Derived() && !*replace {
		return fmt.Errorf("%s/%s already exists as a stored secret holding a value of its own.\n"+
			"Re-run with --replace to compose it from other secrets instead; its stored value is kept "+
			"in history but stops being used", *project, *name)
	}

	// Resolve before committing. A derivation that cannot expand is a secret
	// that will fail every render from now on, and the moment the operator can
	// still fix it cheaply is now, while they are looking at the template.
	origin := derive.Ref{Project: *project, Name: *name}
	if _, err := derive.Resolve(origin, *from, resolve.Lookup(a.st, a.key)); err != nil {
		return fmt.Errorf("%w\n(the derivation was not saved)", err)
	}

	verb := "derived"
	switch {
	case existing != nil && existing.Derived():
		verb = "re-derived"
	case existing != nil:
		verb = "converted to derived"
	}
	_, _, err = store.MutateValue(a.st, func(m *store.Mutation) (*store.Secret, store.AuditRecord, error) {
		sec := existing
		if sec == nil {
			created, err := m.CreateSecret(*project, *name, *scope, false, "")
			if err != nil {
				return nil, store.AuditRecord{}, err
			}
			sec = created
		}
		if err := m.SetDerivation(sec.ID, *from); err != nil {
			return nil, store.AuditRecord{}, err
		}
		return sec, store.AuditRecord{
			Actor: cliActor(), Action: "secret.derive", SecretID: sec.ID,
			Details:   fmt.Sprintf("%s %s/%s from %s", verb, *project, *name, *from),
			EventKind: store.KindSecretWrite, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}, nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("%s %s/%s\n", verb, *project, *name)
	for _, ref := range tmpl.Refs() {
		fmt.Printf("  ← %s\n", ref.QualifiedIn(*project))
	}
	fmt.Println("no value is stored; it is expanded on every render, reveal and sync")
	// Same gap `set` warns about, and easier to fall into here: a newly derived
	// secret that no file target manages is a value nothing will ever write.
	warnUndelivered(a, *project, *name)
	return nil
}

// clearDerivation turns a derived secret back into an ordinary one.
//
// It exists because keeping a converted secret's old versions is only a real
// safety net if there is a way to get back to them — otherwise "the stored
// value is kept in history" describes data that can never be read again, which
// is indistinguishable from having deleted it.
//
// A secret converted with --replace returns to its last stored value. One
// created as derived has none, and is refused rather than left as an entry with
// no value at all: signet has no way to delete a secret, so that state would be
// permanent and invisible.
func (a *app) clearDerivation(sec *store.Secret, project, name string) error {
	if sec == nil {
		return fmt.Errorf("no secret %s/%s", project, name)
	}
	if !sec.Derived() {
		return fmt.Errorf("%s/%s is not derived", project, name)
	}
	// The one deliberate read that does not go through resolve, and the reason
	// is the point: this asks what is *behind* the derivation, which resolve
	// will never answer — Current short-circuits on Derived() and reports the
	// computed value. Reading the version directly is the only way to know
	// whether clearing the derivation leaves anything at all.
	cur, err := a.st.CurrentVersion(sec.ID)
	if err != nil {
		return err
	}
	if cur == nil {
		return fmt.Errorf("%s/%s was created as a derived secret and has no stored value to fall back to.\n"+
			"Clearing its derivation would leave an entry with no value and no way to remove it; "+
			"use `signet set` to give it one first, or leave it derived", project, name)
	}
	was := sec.Derivation
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if err := m.SetDerivation(sec.ID, ""); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "secret.derive.clear", SecretID: sec.ID,
			Details: fmt.Sprintf("cleared derivation of %s/%s (was %s) · version %d #%s is current again",
				project, name, was, cur.VersionNo, cur.VHash),
			EventKind: store.KindSecretWrite, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeUpdated},
		}, nil
	}); err != nil {
		return err
	}
	fmt.Printf("%s/%s is no longer derived — version %d #%s is current again\n",
		project, name, cur.VersionNo, cur.VHash)
	fmt.Println("its value can drift from what it was composed from again; `signet set` now works on it")
	return nil
}

// ---- render -----------------------------------------------------------------

// runRender writes each of the project's file targets from the vault.
//
// The write is a merge, not a replacement: the managed keys get the vault's
// current values and every other line of the file — comments, blank lines, key
// order, keys signet does not manage — is left as it was found. These files are
// hand-maintained and gitignored, so a canonical rewrite would delete live
// credentials and the structure organizing them with no copy to restore from,
// and render is reached for precisely when a file is already in trouble.
// Dropping the unmanaged keys is available, but only by asking for it: --prune.
func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	check := fs.Bool("check", false, "report drift without writing")
	prune := fs.Bool("prune", false, "delete keys the target does not manage instead of keeping them")
	against := fs.String("against", "", "with --check: an env file to compare the rendered key sets against")
	fs.Parse(args)
	if *project == "" {
		return fmt.Errorf("usage: signet render --project <p> [--check [--against </path/to/.env>]] [--prune]")
	}
	if *against != "" && !*check {
		return fmt.Errorf("--against reports what a render would differ from, so it only makes sense with --check")
	}
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	targets, err := a.st.FileTargetsForProject(*project)
	if err != nil {
		return err
	}
	renderTargets, err := a.st.RenderTargetsForProject(*project)
	if err != nil {
		return err
	}
	if len(targets) == 0 && len(renderTargets) == 0 {
		return fmt.Errorf("project %s has no file targets (import an env file first)", *project)
	}
	// Rejected rather than ignored. --against exists to answer one question —
	// what would the environment lose — and with no rendered target to ask it
	// of, the honest answer is not "nothing": it is that the comparison never
	// ran. Accepting the flag and printing a clean report would be the same
	// false all-clear the flag was added to prevent.
	if *against != "" && len(renderTargets) == 0 {
		return fmt.Errorf("--against compares what a rendered target would deliver against a live file, and project %s has no rendered targets — attach one with `signet target add --project %s --render-as-secret …`", *project, *project)
	}
	// --check is a report, so it must survive the state it exists to report on.
	// The strict resolve is what a write needs; making the check depend on it
	// too would mean the command that answers "what is wrong" refuses to run
	// precisely when something is.
	if *check {
		want, problems, err := a.projectValues(*project)
		if err != nil {
			return err
		}
		// Named up front, because this is the state that stops `signet render`
		// working at all. A secret that cannot be resolved is simply absent
		// from want, and every drift check below compares against an absent
		// value as though it were an empty one — so without this the report
		// would describe a broken derivation as a key whose value has changed,
		// and point at a write that would refuse to run.
		if len(problems) > 0 {
			fmt.Printf("%d secret(s) in %s cannot be resolved — `signet render` refuses to write while this is true:\n", len(problems), *project)
			for _, name := range sortedKeys(problems) {
				fmt.Printf("  %-40s %s\n", name, problems[name])
			}
		}
		for _, t := range targets {
			cfg, err := t.FileConfig()
			if err != nil {
				return err
			}
			// --check --prune is the dry run for a delete that cannot be undone,
			// so it is answered rather than rejected: same report, framed as what
			// --prune would take.
			printDrift(syncpkg.CheckFile(cfg.Path, want, cfg.Keys), *prune, problems)
		}
		blocked := false
		for i := range renderTargets {
			b, err := printRenderCheck(&renderTargets[i], *project, want, problems, *against, a.key)
			if err != nil {
				return err
			}
			blocked = blocked || b
		}
		// Non-zero so this is gateable from a deploy script. Returned rather than
		// os.Exit'd: the report above is the useful output either way, and an
		// exit here would take the process down mid-command, past the deferred
		// close and out of reach of any test.
		if blocked {
			return errRenderCheckBlocked
		}
		return nil
	}
	want, err := a.projectValuesStrict(*project)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("project %s has only rendered targets, which `signet sync` delivers — there is no file to write", *project)
	}

	for _, t := range targets {
		cfg, err := t.FileConfig()
		if err != nil {
			return err
		}
		var pairs []envfile.Pair
		for _, k := range cfg.Keys {
			v, ok := want[k]
			if !ok {
				return fmt.Errorf("file target %s wants key %s but the vault has no %s/%s", cfg.Path, k, *project, k)
			}
			pairs = append(pairs, envfile.Pair{Key: k, Value: v})
		}
		content, unmanaged, err := envfile.RenderInto(cfg.Path, pairs, *prune)
		if err != nil {
			return fmt.Errorf("%w — refusing to overwrite a file signet cannot read; fix it or move it aside", err)
		}
		if err := atomicWrite(cfg.Path, content, cfg.Mode); err != nil {
			return err
		}
		// What happened to keys signet does not manage belongs in the ledger as
		// much as on the terminal: --prune deletes credentials signet has no
		// record of and therefore cannot restore, so the entry has to name them.
		note := ""
		if len(unmanaged) > 0 {
			verb := "kept"
			if *prune {
				verb = "DELETED"
			}
			note = fmt.Sprintf(", %d unmanaged %s: %s", len(unmanaged), verb, strings.Join(unmanaged, ", "))
		}
		// The file is already written, so a failure here cannot be undone — but
		// it leaves the target's recorded state describing the render before
		// this one, which is worth saying out loud rather than dropping.
		if err := a.st.UpdateTargetPush(t.ID, "in sync", "", &store.PushProvenance{}, time.Now().UTC().Format(time.RFC3339)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rendered %s but could not record its state: %v\n", cfg.Path, err)
		}
		if _, err := a.st.AppendAudit(store.AuditRecord{
			Actor: cliActor(), Action: "render", TargetID: t.ID,
			Details:   fmt.Sprintf("rendered %d keys → %s (mode %s)%s", len(pairs), cfg.Path, cfg.Mode, note),
			EventKind: store.KindRender, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}); err != nil {
			return err
		}
		fmt.Printf("rendered %s (%d keys%s)\n", cfg.Path, len(pairs), note)
	}
	// A rendered target delivers over the network, not to disk, so this command
	// cannot touch it — but staying silent let `render` report success while
	// leaving the environment holding the values the file no longer has. The
	// operator's next step is a sync, and nothing else was going to say so.
	//
	// What it must not do is assert that without checking. Writing a file target
	// does not make a rendered one stale; the vault having moved on since its
	// last push does, and renderState is what answers that — the same answer
	// `--check` and `status` report, so the three cannot describe one target
	// three ways.
	if len(renderTargets) > 0 {
		fmt.Printf("%d rendered target(s) in %s were not written — they deliver to GitHub, not to disk:\n", len(renderTargets), *project)
		undelivered := 0
		for i := range renderTargets {
			cfg, err := renderTargets[i].GHRenderConfig()
			if err != nil {
				return err
			}
			note := renderedTargetNote(&renderTargets[i], renderState(&renderTargets[i], cfg, want, a.key))
			if note.wantsSync {
				undelivered++
			}
			fmt.Printf("  %s (%d keys) — %s\n", cfg.Destination(), len(cfg.Keys), note.text)
			// A target whose next step is not the group's names it under
			// itself, since the trailing line below speaks for all of them and
			// cannot say something different about one.
			if note.hint != "" {
				fmt.Printf("    %s\n", fmt.Sprintf(note.hint, *project))
			}
		}
		// Suggested only when a sync would actually do something. A next step
		// printed after a report that says nothing is pending is how an operator
		// learns to skip the line, including on the run where it matters.
		if undelivered > 0 {
			fmt.Printf("run `signet sync` to deliver them\n")
		}
	}
	return nil
}

// renderNote is how one rendered target is reported at the end of a write:
// the wording, whether a sync is the next step, and an optional per-target
// follow-up line that takes the project name.
type renderNote struct {
	text      string
	wantsSync bool
	hint      string
}

// renderedTargetNote words a rendered target's state for the end of a write.
//
// The states divide in two, and the division is the point: "empty" and
// "incomplete" are conditions sync *refuses*, so telling the operator to run one
// sends them at a command that will decline. The rest are conditions sync
// resolves. Only the second group earns the suggestion.
//
// The wording deliberately reuses the tokens `render --check` prints for the
// same conditions — EMPTY, INCOMPLETE, never pushed — so that an operator
// grepping a terminal for one of them finds both commands rather than whichever
// they happened to run.
func renderedTargetNote(t *store.Target, state string) renderNote {
	switch state {
	case "empty":
		return renderNote{text: "EMPTY — this target manages no keys, so sync will refuse it rather than deliver an empty environment"}
	case "incomplete":
		return renderNote{
			text: "INCOMPLETE — managed key(s) have no value in the vault, so sync will refuse it",
			hint: "signet render --project %s --check    # names them",
		}
	case "never":
		// Not "stale", which would claim this render made it so — it has never
		// been delivered at all. That is also a different next step, and the
		// hint has to say so rather than leave the group's `signet sync` line
		// to imply otherwise: the first push is the one no other guard covers,
		// since there is no previous delivery to compare against and the
		// destination cannot be read back. --against is that guard, and
		// printRenderCheck names it for the same target in the same situation.
		return renderNote{
			text:      "never pushed — the environment does not have these values yet",
			wantsSync: true,
			hint:      "signet render --project %s --check --against /path/to/the/live/.env    # before the first sync",
		}
	case "drift":
		return renderNote{text: "now stale", wantsSync: true}
	case "unknown":
		return renderNote{text: "delivered once, before signet recorded fingerprints — currency unknown until the next push", wantsSync: true}
	case "error":
		// The reason is carried rather than summarized, because this is the
		// only place in the CLI that prints it: `status`, `target list` and
		// `render --check` all show the bare state word, so "error" alone would
		// leave `signet audit` as the only way to learn why.
		//
		// GHState returns "error" only when LastError is non-empty, so there is
		// no empty-reason branch to write.
		return renderNote{text: fmt.Sprintf("last push failed (%s)", t.LastError), wantsSync: true}
	case "in sync":
		return renderNote{text: "in sync — this render changed nothing it delivers"}
	default:
		// A state this function has not been taught is reported as itself and
		// counted as undelivered. Folding it into the in-sync wording would
		// make a word nobody has checked read as an all-clear and suppress the
		// sync suggestion — which is this bug exactly, one state along.
		return renderNote{text: state, wantsSync: true}
	}
}

// projectValues resolves every current value of a project into a map, and
// reports per-secret failures separately rather than as one error for the
// project.
//
// The split exists because two callers want opposite things from the same
// failure. render must refuse: writing a file that silently omits a key it
// manages is how a half-configured container gets deployed. status must not:
// it loops every project, and one unresolvable derivation taking down the whole
// listing means the operator cannot see the vault at the moment they most need
// to — including the entry that is broken.
func (a *app) projectValues(project string) (map[string]string, map[string]error, error) {
	secrets, err := a.st.ListSecrets()
	if err != nil {
		return nil, nil, err
	}
	want := map[string]string{}
	problems := map[string]error{}
	for _, sec := range secrets {
		if sec.Project != project {
			continue
		}
		r, err := resolve.Current(a.st, a.key, &sec)
		switch {
		case errors.Is(err, resolve.ErrNoVersion):
			// Absent, not broken — the state every secret passes through
			// between creation and its first value.
			continue
		case err != nil:
			problems[sec.Name] = err
			continue
		}
		want[sec.Name] = r.Value
	}
	return want, problems, nil
}

// ghDrift returns what GHState needs to judge a secret's gh-actions
// destinations: the current version for a stored secret, or the digest of the
// resolved value for a derived one, which has no version to compare.
//
// A derivation that cannot resolve returns an error rather than an empty
// digest. Empty means "not derived" to GHState, which would send an
// unresolvable secret down the version path, find no version, and answer "in
// sync" — the most confident possible answer about the one secret nobody can
// currently compute.
func (a *app) ghDrift(sec *store.Secret) (*store.Version, string, error) {
	r, err := resolve.Current(a.st, a.key, sec)
	if err != nil {
		return nil, "", err
	}
	return r.Version, r.Digest, nil
}

// projectValuesStrict is projectValues for callers that must not proceed on a
// partial answer — render, which would otherwise write a file missing a key it
// is responsible for.
func (a *app) projectValuesStrict(project string) (map[string]string, error) {
	want, problems, err := a.projectValues(project)
	if err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(problems) {
		return nil, fmt.Errorf("%s/%s cannot be resolved: %w", project, name, problems[name])
	}
	return want, nil
}

// sortedKeys returns a map's keys in order, so a failure reports the same
// secret every time rather than whichever the map happened to yield first.
func sortedKeys(m map[string]error) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// errRenderCheckBlocked is the verdict of `render --check` when it found a
// condition that would stop a push: keys that would be dropped, a target that
// manages nothing, or managed keys the vault cannot resolve. The report itself
// has already been printed; this exists to carry the exit code, which is the
// only part of it a deploy script can act on.
var errRenderCheckBlocked = errors.New("rendered target(s) would not deliver what the live environment has — see the report above")

// printRenderCheck reports what a rendered target would deliver, and — given a
// reference env file — how that differs from what is deployed today.
//
// The comparison exists because a rendered target's first push is the one no
// other guard covers. Afterwards signet can compare against its own record of
// the last push and refuse a shrinking render; before it, there is no record,
// and the destination's value cannot be read back. A live env file is the only
// evidence available of what the environment actually holds, so this is the
// step that turns "the vault is presumably complete" into something checked.
//
// Keys the reference has and the render lacks are the dangerous direction and
// are named individually: each is a value that would go empty in the deployed
// environment on the next deploy. The other direction is reported too, but as a
// count — an added key is a change worth seeing, not a hazard.
//
// It reports whether it found a condition that should stop a first push: an
// empty or incomplete target, or a render that would drop keys the reference
// has. That answer is what gives the command an exit code, and an exit code is
// the only part of this report a deploy script can read — printing WOULD DROP
// and exiting 0 made the safety story in the README unusable from anything but
// a human's eyes.
func printRenderCheck(t *store.Target, project string, want map[string]string, problems map[string]error, against string, key []byte) (bool, error) {
	cfg, err := t.GHRenderConfig()
	if err != nil {
		return false, err
	}
	fmt.Printf("%s → %s (%d keys)\n", project, cfg.Destination(), len(cfg.Keys))

	if len(cfg.Keys) == 0 {
		// No diff is worth printing against a target that manages nothing: it
		// would list the reference file's every key as one that would be
		// dropped, which is true and useless.
		fmt.Printf("  EMPTY — this target manages no keys, so sync will refuse it rather than deliver an empty environment\n")
		fmt.Printf("    signet target add-key --project %s --gh-secret %s --name NAME\n", project, cfg.SecretName)
		return true, nil
	}
	blocking := false

	// Reported before any diff, because an incomplete render is not a
	// difference of opinion with the reference file — it is a push that will be
	// refused whatever the reference says.
	var missing []string
	for _, k := range cfg.Keys {
		if _, ok := want[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		blocking = true
		sort.Strings(missing)
		fmt.Printf("  INCOMPLETE — %d managed key(s) have no value in the vault, so sync will refuse this target:\n", len(missing))
		for _, k := range missing {
			reason := "no value set"
			if err, broken := problems[k]; broken {
				reason = err.Error()
			}
			fmt.Printf("    %-40s %s\n", k, reason)
		}
	} else {
		// renderState rather than an inline GHState: `status`, this report and
		// the note at the end of a write all answer "is this destination
		// current?", and a second copy of the answer is how they would come to
		// disagree. The branches above have already excluded the two states it
		// reports that this one words for itself.
		fmt.Printf("  state: %s\n", renderState(t, cfg, want, key))
	}

	if against == "" {
		if t.LastPushedAt == "" {
			fmt.Printf("  never pushed — compare against the live environment before the first sync:\n")
			fmt.Printf("    signet render --project %s --check --against /path/to/the/live/.env\n", project)
		}
		return blocking, nil
	}

	pairs, err := envfile.ParseFile(against)
	if err != nil {
		return false, fmt.Errorf("--against %s: %w", against, err)
	}
	managed := map[string]bool{}
	for _, k := range cfg.Keys {
		managed[k] = true
	}
	var absent []string
	for _, p := range pairs {
		if !managed[p.Key] {
			absent = append(absent, p.Key)
		}
	}
	added := 0
	have := envfile.Map(pairs)
	for _, k := range cfg.Keys {
		if _, ok := have[k]; !ok {
			added++
		}
	}
	if len(absent) > 0 {
		blocking = true
		sort.Strings(absent)
		fmt.Printf("  WOULD DROP %d key(s) that %s has and this render does not:\n", len(absent), against)
		for _, k := range absent {
			fmt.Printf("    %s\n", k)
		}
		fmt.Printf("  each would be delivered absent, and read as empty by whatever consumes the file\n")
		fmt.Printf("  import them into the vault, then `signet target add-key --project %s --gh-secret %s --name ...`\n", project, cfg.SecretName)
	} else {
		fmt.Printf("  covers every key in %s\n", against)
	}
	if added > 0 {
		fmt.Printf("  and would add %d key(s) that %s does not have\n", added, against)
	}
	return blocking, nil
}

// printDrift reports one file target's state. With prune set the report is the
// dry run for `render --prune`, so the unmanaged keys are framed as what that
// write would delete rather than what an ordinary one would keep.
// problems names the project's unresolvable secrets, so a key whose value
// could not be computed is reported as that rather than as drift: it is absent
// from the comparison map, which makes it indistinguishable from a key whose
// value is the empty string, and calling it "changed" promises a repair that
// `render` will decline to attempt.
func printDrift(d syncpkg.FileDrift, prune bool, problems map[string]error) {
	switch {
	case d.MissingFile:
		fmt.Printf("%s: MISSING FILE\n", d.Path)
		return
	case d.Unreadable != "":
		fmt.Printf("%s: UNREADABLE — render will refuse this file rather than overwrite it\n", d.Path)
		fmt.Printf("  %s\n", d.Unreadable)
		return
	case d.Clean() && !anyUnresolved(d, problems):
		fmt.Printf("%s: in sync (%d keys)\n", d.Path, len(d.Keys))
	default:
		fmt.Printf("%s: DRIFT\n", d.Path)
		for _, k := range d.Keys {
			if _, broken := problems[k.Key]; broken {
				fmt.Printf("  %-40s %s\n", k.Key, "unresolved — no value to compare")
				continue
			}
			if k.State != "ok" {
				fmt.Printf("  %-40s %s\n", k.Key, k.State)
			}
		}
	}
	if len(d.Unmanaged) > 0 {
		if prune {
			fmt.Printf("  --prune WOULD DELETE these keys, which signet has no copy of: %s\n", strings.Join(d.Unmanaged, ", "))
			return
		}
		fmt.Printf("  unmanaged keys in file (kept on render, --prune deletes them): %s\n", strings.Join(d.Unmanaged, ", "))
	}
}

// atomicWrite replaces path's contents via a temp file in the same directory and
// a rename.
//
// mode applies to a file being created. An existing file keeps the mode and
// ownership it already has: those are as much a deliberate part of a
// hand-maintained file as its contents, and the recorded mode is not a
// considered alternative — import hardcodes 0600 for every target it registers,
// so honouring it here would silently revert a 0640 set for a service group
// every time the file was rendered.
//
// Ownership is restored best-effort, and only where the caller has the privilege
// to restore it. A rename replaces a file the caller could never have opened for
// writing, so an unprivileged render of a service-owned file would otherwise take
// it over quietly; when the chown is refused, so is the write.
func atomicWrite(path, content, mode string) error {
	perm := os.FileMode(0o600)
	if mode != "" {
		var parsed uint32
		if _, err := fmt.Sscanf(mode, "%o", &parsed); err == nil {
			perm = os.FileMode(parsed)
		}
	}
	var owner *syscall.Stat_t
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
		owner, _ = st.Sys().(*syscall.Stat_t)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".signet-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if owner != nil && (int(owner.Uid) != os.Getuid() || int(owner.Gid) != os.Getgid()) {
		if err := tmp.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
			tmp.Close()
			return fmt.Errorf("%s belongs to uid %d:%d and this cannot be preserved: %w", path, owner.Uid, owner.Gid, err)
		}
	}
	// The content has to be on the disk before the rename publishes it, and the
	// rename has to be on the disk before this returns. Without both, a crash can
	// leave a file that exists and is empty — which for these files means the
	// unmanaged credentials in them are gone, with no copy anywhere.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ---- target -----------------------------------------------------------------

const targetUsage = `usage:
  signet target list [--secret <p>/<NAME>] [--project <p>]
  signet target add --secret <p>/<NAME> --gh-repo owner/name [--gh-environment ENV] [--gh-secret NAME] [--no-preflight]
  signet target add --project <p> --render-as-secret --gh-repo owner/name --gh-secret NAME [--gh-environment ENV] [--seed-from </path/to/.env>]
  signet target add-key --project <p> --path </path/to/.env> --name NAME[,NAME…]
  signet target add-key --project <p> --gh-secret NAME --name NAME[,NAME…]
  signet target rm  --secret <p>/<NAME> --gh-repo owner/name [--gh-environment ENV] [--gh-secret NAME]
  signet target rm  --project <p> --path </path/to/.env>
  signet target rm  --project <p> --gh-repo owner/name --gh-secret NAME [--gh-environment ENV]`

func runTarget(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", targetUsage)
	}
	switch args[0] {
	case "list":
		return runTargetList(args[1:])
	case "rm":
		return runTargetRm(args[1:])
	case "add":
		return runTargetAdd(args[1:])
	case "add-key":
		return runTargetAddKey(args[1:])
	default:
		return fmt.Errorf("%s", targetUsage)
	}
}

// runTargetAddKey brings existing vault secrets into a file target's key set, so
// render starts writing them.
//
// It is the other half of the gap warnUndelivered reports. Before this, the only
// thing that widened a target's key set was import, which reads the file — so
// delivering a key that was never in the file meant writing a placeholder in by
// hand and importing it back, overwriting the real value with the placeholder on
// the way through.
func runTargetAddKey(args []string) error {
	fs := flag.NewFlagSet("target add-key", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	path := fs.String("path", "", "rendered file path (file targets)")
	ghSecret := fs.String("gh-secret", "", "destination secret name (rendered targets)")
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (rendered targets, when --gh-secret is ambiguous)")
	ghEnv := fs.String("gh-environment", "", "deployment environment (rendered targets, when --gh-secret is ambiguous)")
	name := fs.String("name", "", "secret name(s) to add, comma-separated (required)")
	fs.Parse(args)
	if *project == "" || *name == "" || (*path == "") == (*ghSecret == "") {
		return fmt.Errorf("%s", targetUsage)
	}
	var names []string
	for _, n := range strings.Split(*name, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("%s", targetUsage)
	}
	if *ghSecret != "" {
		return runTargetAddKeyRender(*project, *ghRepo, *ghEnv, *ghSecret, names)
	}
	// Normalized the way import records it. A relative --path would match no
	// target, and the "import it first" error that follows would send the
	// operator to the one command that *does* normalize — which would match,
	// re-import the file's on-disk values over the vault's, and undo whatever
	// they had just set. Sending someone into a data-loss path over a leading
	// "./" is precisely the failure this command was added to remove.
	abs, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	// Every name has to exist first. A target listing a key the vault cannot
	// supply is not a partial success — render refuses the whole file over one
	// missing value, so a typo here would take the other keys down with it.
	for _, n := range names {
		sec, err := a.st.GetSecret(*project, n)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("no secret %s/%s — set it before adding it to a target", *project, n)
		}
	}

	// The key count and the outcome are what the transaction decided, so they
	// come back through MutateValue rather than a captured variable: a value
	// assigned inside a transaction that then rolls back has no claim to be read.
	res, _, err := store.MutateValue(a.st, func(m *store.Mutation) (addKeyResult, store.AuditRecord, error) {
		// Looked up inside the transaction that writes: UpsertFileTarget creates
		// a target when it finds no match, and this command widens an existing
		// one. Checking outside would leave a window where a `target rm` between
		// the two turns "add a key" into "attach a new file".
		existing, err := m.FindFileTarget(*project, abs)
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		if existing == nil {
			return addKeyResult{}, store.AuditRecord{}, fmt.Errorf("no file target %s in project %s — `signet import` it first", abs, *project)
		}
		t, outcome, err := m.UpsertFileTarget(*project, abs, names, "")
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		cfg, err := t.FileConfig()
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		res := addKeyResult{keys: len(cfg.Keys), outcome: outcome}
		return res, store.AuditRecord{
			Actor: cliActor(), Action: "target.file", TargetID: t.ID,
			Details:   fmt.Sprintf("%s → %s +%s (%d keys)", *project, abs, strings.Join(names, ", "), res.keys),
			EventKind: store.KindTargetConfig, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return err
	}
	// An upsert that changed nothing is not an update, and telling someone to go
	// render would imply a pending change that does not exist.
	if res.outcome == store.OutcomeUnchanged {
		fmt.Printf("target unchanged: %s → %s already manages %s\n", *project, abs, strings.Join(names, ", "))
		return nil
	}
	fmt.Printf("target updated: %s → %s now manages %d keys\n", *project, abs, res.keys)
	fmt.Printf("run `signet render --project %s` to write them\n", *project)
	return nil
}

// addKeyResult is what runTargetAddKey's transaction reports back to its caller.
type addKeyResult struct {
	keys    int
	outcome store.Outcome
}

// runTargetAddKeyRender widens a rendered target's key set, so the next sync
// carries those keys into the destination environment.
//
// Every name has to exist in the vault first, for the same reason the file
// variant insists: the push is refused outright if any managed key cannot be
// resolved, so a typo here would stop the whole environment from syncing rather
// than just its own key.
func runTargetAddKeyRender(project, ghRepo, ghEnv, ghSecret string, names []string) error {
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	// Existence is not the property that matters. A push refuses on any key it
	// cannot *resolve*, so a secret row whose value is missing or whose
	// derivation is broken arms exactly the refusal this check is documented as
	// preventing — and arms it for the whole environment, not just this key.
	// Resolving here is what makes the doc comment above true.
	want, problems, err := a.projectValues(project)
	if err != nil {
		return err
	}
	for _, n := range names {
		sec, err := a.st.GetSecret(project, n)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("no secret %s/%s — set it before adding it to a target", project, n)
		}
		if _, ok := want[n]; !ok {
			reason := "it has no value"
			if perr, broken := problems[n]; broken {
				reason = perr.Error()
			}
			return fmt.Errorf("%s/%s cannot be resolved (%s) — adding it would make `signet sync` refuse the whole rendered target; fix it first", project, n, reason)
		}
	}

	res, _, err := store.MutateValue(a.st, func(m *store.Mutation) (addKeyResult, store.AuditRecord, error) {
		t, err := findRenderTargetTx(m, project, ghRepo, ghEnv, ghSecret)
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		t, outcome, err := m.AddRenderKeys(t, names)
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return addKeyResult{}, store.AuditRecord{}, err
		}
		return addKeyResult{keys: len(cfg.Keys), outcome: outcome}, store.AuditRecord{
			Actor: cliActor(), Action: "target.render", TargetID: t.ID,
			Details: fmt.Sprintf("%s render → %s +%s (%d keys)",
				project, cfg.Destination(), strings.Join(names, ", "), len(cfg.Keys)),
			EventKind: store.KindTargetConfig, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return err
	}
	if res.outcome == store.OutcomeUnchanged {
		fmt.Printf("target unchanged: %s render → %s already manages %s\n", project, ghSecret, strings.Join(names, ", "))
		return nil
	}
	fmt.Printf("target updated: %s render → %s now manages %d keys\n", project, ghSecret, res.keys)
	fmt.Printf("run `signet sync` to deliver them\n")
	return nil
}

// findRenderTargetTx resolves the project's rendered target from as much of the
// destination as the caller named, inside the caller's transaction.
//
// A project will almost always have one, so requiring the full repo and
// environment on every add-key would be ceremony. Ambiguity is refused rather
// than resolved by picking the first, because the two candidates are different
// live environments and delivering a key to the wrong one is silent.
func findRenderTargetTx(m *store.Mutation, project, ghRepo, ghEnv, ghSecret string) (*store.Target, error) {
	if ghRepo != "" {
		t, err := m.FindGHRenderTarget(project, ghRepo, ghEnv, ghSecret)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, fmt.Errorf("no rendered target %s → %s in project %s", ghSecret, ghRepo, project)
		}
		return t, nil
	}
	all, err := m.RenderTargetsForProject(project)
	if err != nil {
		return nil, err
	}
	var matches []*store.Target
	var dests []string
	for i := range all {
		cfg, err := all[i].GHRenderConfig()
		if err != nil {
			return nil, err
		}
		if cfg.SecretName != ghSecret {
			continue
		}
		// An explicitly named environment narrows the search rather than being
		// discarded. Ignoring it would let `--gh-environment prod` resolve to
		// the one target named PROD_ENV_FILE even when that target is scoped to
		// staging — delivering a key to a live environment the caller named and
		// did not get, which is the precise hazard the ambiguity check below
		// exists to refuse.
		if ghEnv != "" && cfg.Environment != ghEnv {
			continue
		}
		matches = append(matches, &all[i])
		dests = append(dests, cfg.Destination())
	}
	switch len(matches) {
	case 0:
		if ghEnv != "" {
			return nil, fmt.Errorf("no rendered target %s scoped to environment %s in project %s — `signet target list --project %s` shows what is attached",
				ghSecret, ghEnv, project, project)
		}
		return nil, fmt.Errorf("no rendered target %s in project %s — `signet target list --project %s` shows what is attached", ghSecret, project, project)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%d rendered targets in project %s are named %s — name one with --gh-repo and --gh-environment: %s",
			len(matches), project, ghSecret, strings.Join(dests, ", "))
	}
}

func runTargetAdd(args []string) error {
	fs := flag.NewFlagSet("target add", flag.ExitOnError)
	ref := fs.String("secret", "", "secret ref project/NAME (required)")
	renderProject := fs.String("project", "", "project (with --render-as-secret)")
	renderAsSecret := fs.Bool("render-as-secret", false, "deliver the project's rendered env file as one secret")
	seedFrom := fs.String("seed-from", "", "file target whose key set to seed a rendered target with")
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (required)")
	ghEnv := fs.String("gh-environment", "", "deployment environment to scope the secret to (default: repository secret)")
	ghSecret := fs.String("gh-secret", "", "destination Actions secret name (default: local name)")
	noPreflight := fs.Bool("no-preflight", false, "skip the check that the PAT can reach the repo")
	fs.Parse(args)
	if *ghRepo == "" || !strings.Contains(*ghRepo, "/") {
		return fmt.Errorf("%s", targetUsage)
	}
	if *renderAsSecret || *renderProject != "" {
		return runTargetAddRender(*renderProject, *renderAsSecret, *seedFrom, *ghRepo, *ghEnv, *ghSecret, *noPreflight)
	}
	if *ref == "" {
		return fmt.Errorf("%s", targetUsage)
	}
	if *seedFrom != "" {
		return fmt.Errorf("--seed-from applies to --render-as-secret targets, which take a --project rather than a --secret")
	}
	project, name, err := parseSecretRef(*ref)
	if err != nil {
		return err
	}
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	sec, err := a.st.GetSecret(project, name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret %s/%s", project, name)
	}
	dest := *ghSecret
	if dest == "" {
		dest = name
	}
	cfg := store.GHConfig{Repo: *ghRepo, SecretName: dest, Environment: *ghEnv}
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		// Checked inside the transaction that inserts, so the destination
		// cannot appear between the check and the write. The API refuses the
		// same duplicate; without this the CLI would quietly attach a second
		// target pushing the same value to the same place.
		dup, err := m.FindGHTarget(sec.ID, *ghRepo, *ghEnv, dest)
		if err != nil {
			return store.AuditRecord{}, err
		}
		if dup != nil {
			return store.AuditRecord{}, fmt.Errorf("target already exists: %s/%s → %s (%s %s)", project, name, *ghRepo, cfg.Scope(), dest)
		}
		// dup only sees this secret's own targets, so it cannot see a rendered
		// target already delivering an env file to the same GitHub secret. Both
		// would PUT the same path and the last writer would win. See
		// FindGHDestination.
		if claimed, err := m.FindGHDestination(*ghRepo, *ghEnv, dest); err != nil {
			return store.AuditRecord{}, err
		} else if claimed != nil {
			return store.AuditRecord{}, fmt.Errorf("%s is already delivered to by a %s target — one GitHub secret holds one value, so two targets would overwrite each other on every sync; detach the existing one first (`signet target list`)",
				cfg.Destination(), claimed.Kind)
		}
		t, err := m.AddGHTarget(sec.ID, *ghRepo, *ghEnv, dest)
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "target.add", SecretID: sec.ID, TargetID: t.ID,
			Details:   fmt.Sprintf("%s/%s → %s · %s %s", project, name, *ghRepo, cfg.Scope(), dest),
			EventKind: store.KindTargetConfig, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		return err
	}
	fmt.Printf("target added: %s/%s → %s (%s %s)\n", project, name, *ghRepo, cfg.Scope(), dest)
	// The add stands either way. A grant that is not in place yet is a normal
	// order of operations — attach the destination, then widen the PAT — and
	// refusing here would make the two commands depend on each other's order for
	// no reason. What is worth changing is when the operator finds out: at the
	// add, not at the next push of an unrelated secret. Skipping the check is
	// not the same as failing it, so --no-preflight leaves the path clear.
	clear := true
	if !*noPreflight {
		clear = preflightGHRepo(preflightClient(a), *ghRepo, *ghEnv)
	}
	if clear {
		fmt.Println("run `signet sync` to push")
	}
	return nil
}

// runTargetAddRender attaches a whole-file rendered destination to a project:
// every key it manages is rendered into env-file content and delivered as the
// value of one GitHub secret.
//
// The key set is seeded from an existing file target rather than defaulting to
// the whole project. "Every secret in the project" is the wrong default in both
// directions — it would carry keys the deployed environment has never had into
// it, and it would make every later `signet set` on the project a silent change
// to a live environment. Seeding from a file target instead starts the render
// as a copy of something already true, and widening it stays an explicit act
// (`target add-key`).
func runTargetAddRender(project string, renderAsSecret bool, seedFrom, ghRepo, ghEnv, ghSecret string, noPreflight bool) error {
	switch {
	case project == "":
		return fmt.Errorf("--render-as-secret needs a --project (the project whose keys are rendered)")
	case !renderAsSecret:
		return fmt.Errorf("--project attaches a rendered target and needs --render-as-secret; a single secret's destination takes --secret <p>/<NAME>")
	case ghSecret == "":
		// No local name to fall back on: the value is a whole file, not a
		// secret whose name could stand in for the destination's.
		return fmt.Errorf("--render-as-secret needs an explicit --gh-secret (the destination secret name, e.g. PROD_ENV_FILE)")
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	keys, seededFrom, err := seedKeys(a, project, seedFrom)
	if err != nil {
		return err
	}

	cfg := store.GHConfig{Repo: ghRepo, SecretName: ghSecret, Environment: ghEnv}
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		dup, err := m.FindGHRenderTarget(project, ghRepo, ghEnv, ghSecret)
		if err != nil {
			return store.AuditRecord{}, err
		}
		if dup != nil {
			return store.AuditRecord{}, fmt.Errorf("target already exists: %s render → %s (%s %s)", project, ghRepo, cfg.Scope(), ghSecret)
		}
		// The collision that matters is with the destination, not with the kind.
		// A gh-actions target already writing this secret would take turns with
		// this one on every sync, each overwriting the other and each reporting
		// "in sync" — and the value that survives would be whichever ran last.
		if claimed, err := m.FindGHDestination(ghRepo, ghEnv, ghSecret); err != nil {
			return store.AuditRecord{}, err
		} else if claimed != nil {
			return store.AuditRecord{}, fmt.Errorf("%s is already delivered to by a %s target — one GitHub secret holds one value, so two targets would overwrite each other on every sync; detach the existing one first (`signet target list`)",
				cfg.Destination(), claimed.Kind)
		}
		t, err := m.AddGHRenderTarget(project, ghRepo, ghEnv, ghSecret, keys)
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "target.add", TargetID: t.ID,
			Details: fmt.Sprintf("%s render (%d keys%s) → %s · %s %s",
				project, len(keys), seededFrom, ghRepo, cfg.Scope(), ghSecret),
			EventKind: store.KindTargetConfig, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		return err
	}

	fmt.Printf("target added: %s render → %s (%s %s)\n", project, ghRepo, cfg.Scope(), ghSecret)
	fmt.Printf("it manages %d keys%s\n", len(keys), seededFrom)
	if len(keys) == 0 {
		fmt.Printf("add keys with `signet target add-key --project %s --gh-secret %s --name NAME`\n", project, ghSecret)
	}
	// Said before any sync is suggested, because the push is atomic and total:
	// whatever this target does not manage is simply absent from the delivered
	// file, and a consumer reads an absent key as an empty one.
	fmt.Printf("check what it would deliver before the first push:\n")
	fmt.Printf("  signet render --project %s --check --against /path/to/the/live/.env\n", project)
	if noPreflight {
		return nil
	}
	if preflightGHRepo(preflightClient(a), ghRepo, ghEnv) {
		fmt.Println("run `signet sync` to push")
	}
	return nil
}

// seedKeys resolves the key set a new rendered target starts with, and the
// phrase describing where it came from.
//
// A project with exactly one file target needs no argument; anything else has
// to be named, because guessing wrong here is not a cosmetic mistake. The key
// set decides the entire content of a live environment, and a target seeded
// from the wrong file would deliver a plausible env file describing the wrong
// deployment.
func seedKeys(a *app, project, seedFrom string) ([]string, string, error) {
	if seedFrom != "" {
		abs, err := filepath.Abs(seedFrom)
		if err != nil {
			return nil, "", err
		}
		t, err := a.st.FindFileTarget(project, abs)
		if err != nil {
			return nil, "", err
		}
		if t == nil {
			return nil, "", fmt.Errorf("no file target %s in project %s — `signet target list --project %s` shows what there is to seed from", abs, project, project)
		}
		cfg, err := t.FileConfig()
		if err != nil {
			return nil, "", err
		}
		return cfg.Keys, ", seeded from " + abs, nil
	}
	// Only needed for the unnamed case: with --seed-from the target is looked up
	// directly, and listing the project's file targets to then discard the list
	// was a query paid for on every add.
	fts, err := a.st.FileTargetsForProject(project)
	if err != nil {
		return nil, "", err
	}
	switch len(fts) {
	case 0:
		return nil, "", nil
	case 1:
		cfg, err := fts[0].FileConfig()
		if err != nil {
			return nil, "", err
		}
		return cfg.Keys, ", seeded from " + cfg.Path, nil
	default:
		var paths []string
		for _, t := range fts {
			cfg, err := t.FileConfig()
			if err != nil {
				return nil, "", err
			}
			paths = append(paths, cfg.Path)
		}
		return nil, "", fmt.Errorf("project %s has %d file targets — name the one to seed from with --seed-from: %s",
			project, len(fts), strings.Join(paths, ", "))
	}
}

// preflightTimeout bounds one probe. Per call rather than across a run: a
// shared budget turns one slow repository into a wave of reports about
// repositories that were never actually asked.
const preflightTimeout = 30 * time.Second

// preflightClient resolves the credential a probe should use, or nil when there
// is none to resolve. The credential is a sync-time requirement, not an
// add-time one, so its absence is reported and stepped over rather than failing
// the command that asked.
func preflightClient(a *app) *syncpkg.GHClient {
	tok, err := ops.ResolveGHTokenFor(a.st, a.key, a.cfg.GitHubToken, cliActor(), cliRole(), ops.PurposePreflight)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight skipped: %v\n", err)
		return nil
	}
	noteTokenSource(tok)
	return syncpkg.NewGHClient(tok.Value)
}

// preflightGHRepo probes whether gh can manage repo's Actions secrets and
// prints the fix when it cannot. It reports whether sync has a clear path to
// the repo: an absent credential or an inconclusive probe counts as clear,
// because neither is evidence against the grant.
//
// It takes the client rather than building one so a test can point it at a
// server that answers the way GitHub does. Without that the entire preflight
// surface would only be reachable by talking to api.github.com for real.
func preflightGHRepo(gh *syncpkg.GHClient, repo, env string) bool {
	if gh == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	probe := gh.CheckRepoAccess(ctx, repo, env)
	// Keyed on whether the probe has anything to say rather than on whether it
	// passed. A probe can succeed and still need reporting — an unsettled write
	// check, or a delete the probe performed — and returning early on AccessOK
	// made `target add` the one caller that saw none of it.
	if msg := probe.Message(); msg != "" {
		// Reported whether or not signet can attribute it: a probe that failed for
		// a reason signet has no name for is still something the operator asked
		// for and did not get.
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
	}
	return !probe.Blocked()
}

// noteTokenSource says out loud when the vault decrypted its own root
// credential to authenticate, and when that credential stops working. The
// arrangement is the documented one, not an incident — but it is not something
// to do silently either, and a PAT that works today and 401s in a month gives
// no other warning.
func noteTokenSource(tok ops.GHToken) {
	if tok.Source != ops.TokenFromVault {
		return
	}
	note := ""
	if s := expiresIn(tok.ExpiresAt); s != "" {
		note = ", expires " + s
	}
	fmt.Fprintf(os.Stderr, "using %s/%s from the vault (%s%s)\n",
		ops.GHTokenProject, ops.GHTokenName, ops.GHTokenEnvNone, note)
}

// runTargetList prints every target, optionally narrowed to one secret or
// project. Sync state is derived, not read back: gh targets compare the last
// pushed version against the secret's current one, and file targets are checked
// against what is actually on disk.
func runTargetList(args []string) error {
	fs := flag.NewFlagSet("target list", flag.ExitOnError)
	ref := fs.String("secret", "", "only targets of this secret (project/NAME)")
	project := fs.String("project", "", "only targets in this project")
	fs.Parse(args)

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	// Resolve the secret filter up front so an unknown ref fails loudly rather
	// than silently printing nothing.
	var wantSecret *store.Secret
	wantProject := *project
	if *ref != "" {
		p, n, err := parseSecretRef(*ref)
		if err != nil {
			return err
		}
		if wantProject != "" && wantProject != p {
			return fmt.Errorf("--secret %s is in project %s, which --project %s excludes", *ref, p, wantProject)
		}
		if wantSecret, err = a.st.GetSecret(p, n); err != nil {
			return err
		}
		if wantSecret == nil {
			return fmt.Errorf("no secret %s/%s", p, n)
		}
		wantProject = p
	}

	targets, err := a.st.ListTargets()
	if err != nil {
		return err
	}

	// projectValues decrypts every secret in the project, so it is cached —
	// but the drift itself is not, because CheckFile depends on the target's
	// own path and key set. Two file targets in one project share the values
	// and nothing else.
	valuesFor := map[string]map[string]string{}
	projectValues := func(project string) (map[string]string, error) {
		if v, ok := valuesFor[project]; ok {
			return v, nil
		}
		// Lenient: a listing that dies on one unresolvable derivation hides
		// every other target, including the ones that are fine.
		v, _, err := a.projectValues(project)
		if err != nil {
			return nil, err
		}
		valuesFor[project] = v
		return v, nil
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	rows := 0
	emit := func(owner, kind, dest, state, synced string) {
		if rows == 0 {
			fmt.Fprintln(w, "SECRET\tKIND\tDESTINATION\tSTATE\tLAST SYNCED")
		}
		rows++
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", owner, kind, dest, state, dashIfEmpty(synced))
	}

	for _, t := range targets {
		switch t.Kind {
		case "gh-actions":
			if wantSecret != nil && t.SecretID != wantSecret.ID {
				continue
			}
			sec, err := a.st.GetSecretByID(t.SecretID)
			if err != nil {
				return err
			}
			if sec == nil || (wantProject != "" && sec.Project != wantProject) {
				continue
			}
			cfg, err := t.GHConfig()
			if err != nil {
				return err
			}
			// Needs the secret's current value fingerprint: "in sync" from the
			// last push is not the same as "still current".
			cur, digest, derr := a.ghDrift(sec)
			state := t.GHState(cur, digest)
			if derr != nil {
				state = "unresolved"
			}
			emit(sec.Project+"/"+sec.Name, t.Kind, cfg.Destination(), state, t.LastPushedAt)

		case "gh-render":
			// Project-scoped like a file target, so a secret filter keeps it
			// only when the render actually carries that key.
			if wantProject != "" && t.Project != wantProject {
				continue
			}
			cfg, err := t.GHRenderConfig()
			if err != nil {
				return err
			}
			if wantSecret != nil && !cfg.Manages(wantSecret.Name) {
				continue
			}
			want, err := projectValues(t.Project)
			if err != nil {
				return err
			}
			owner := t.Project + fmt.Sprintf(" (%d keys)", len(cfg.Keys))
			if wantSecret != nil {
				owner = t.Project + "/" + wantSecret.Name
			}
			emit(owner, t.Kind, cfg.Destination(), renderState(&t, cfg, want, a.key), t.LastPushedAt)

		case "file":
			// File targets belong to a project rather than one secret, so a
			// secret filter keeps one only when it manages that key.
			if wantProject != "" && t.Project != wantProject {
				continue
			}
			cfg, err := t.FileConfig()
			if err != nil {
				return err
			}
			if wantSecret != nil && !cfg.Manages(wantSecret.Name) {
				continue
			}
			want, err := projectValues(t.Project)
			if err != nil {
				return err
			}
			drift := syncpkg.CheckFile(cfg.Path, want, cfg.Keys)
			// Under a secret filter, report that key's state — collapsing the
			// whole file could pin another key's drift on the one asked about.
			key := ""
			owner := t.Project + fmt.Sprintf(" (%d keys)", len(cfg.Keys))
			if wantSecret != nil {
				key = wantSecret.Name
				owner = t.Project + "/" + wantSecret.Name
			}
			emit(owner, t.Kind, cfg.Path, fileState(drift, key), t.LastPushedAt)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if rows == 0 {
		fmt.Println("no targets matched")
	}
	return nil
}

// anyUnresolved reports whether the target manages a key the project could not
// resolve. Such a key can compare equal by accident — an unresolvable secret is
// absent from the wanted map, so a file holding an empty value for it looks
// like a match — and a file target reported "in sync" on that basis is making
// the one claim it has no evidence for.
func anyUnresolved(d syncpkg.FileDrift, problems map[string]error) bool {
	for _, k := range d.Keys {
		if _, broken := problems[k.Key]; broken {
			return true
		}
	}
	return false
}

// renderState reduces a rendered target's drift to one word.
//
// The blob is delivered and compared whole, so there is no per-key state to
// report: every key it carries shares the destination's currency. What a single
// key can do is stop the whole render — a managed key the vault cannot supply
// makes the next push a refusal, and "incomplete" says that before a sync
// discovers it rather than after.
func renderState(t *store.Target, cfg store.GHRenderConfig, want map[string]string, key []byte) string {
	if len(cfg.Keys) == 0 {
		// Distinct from "incomplete": nothing is missing, the target simply has
		// no keys yet. Sync refuses it either way, but the fix is a different
		// one and reporting both as incomplete would send the reader looking
		// for a value that was never asked for.
		return "empty"
	}
	content, err := syncpkg.RenderBlob(cfg, t.Project, want)
	if err != nil {
		return "incomplete"
	}
	return t.GHState(nil, vault.ValueDigest(key, content))
}

// fileState reduces a file target's drift to one word. With key set it reports
// only that key; otherwise it collapses the whole file, worst state first.
func fileState(d syncpkg.FileDrift, key string) string {
	if d.MissingFile {
		return "missing"
	}
	if d.Unreadable != "" {
		return "unreadable"
	}
	for _, ks := range d.Keys {
		if key != "" && ks.Key != key {
			continue
		}
		if ks.State != "ok" {
			return ks.State
		}
	}
	return "in sync"
}

// runTargetRm detaches a target. It removes signet's record only — whatever is
// already at the destination stays put — which the output says plainly, because
// "removed" could otherwise be read as having deleted the remote secret.
func runTargetRm(args []string) error {
	fs := flag.NewFlagSet("target rm", flag.ExitOnError)
	ref := fs.String("secret", "", "secret ref project/NAME (gh targets)")
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (gh and rendered targets)")
	ghEnv := fs.String("gh-environment", "", "deployment environment the secret is scoped to")
	ghSecret := fs.String("gh-secret", "", "destination Actions secret name (default: local name)")
	project := fs.String("project", "", "project (file and rendered targets)")
	path := fs.String("path", "", "rendered file path (file targets)")
	fs.Parse(args)

	ghMode := *ref != "" || (*ghRepo != "" && *project == "")
	fileMode := *project != "" && *path != ""
	renderMode := *project != "" && *path == ""
	switch {
	case ghMode && (fileMode || renderMode):
		return fmt.Errorf("choose one: --secret/--gh-repo for a GitHub target, or --project for a file or rendered target")
	case ghMode && (*ref == "" || *ghRepo == ""):
		return fmt.Errorf("%s", targetUsage)
	case renderMode && (*ghRepo == "" || *ghSecret == ""):
		return fmt.Errorf("removing a rendered target needs --gh-repo and --gh-secret; removing a file target needs --path")
	case !ghMode && !fileMode && !renderMode:
		return fmt.Errorf("%s", targetUsage)
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	if renderMode {
		t, err := a.st.FindGHRenderTarget(*project, *ghRepo, *ghEnv, *ghSecret)
		if err != nil {
			return err
		}
		if t == nil {
			return fmt.Errorf("no rendered target %s → %s in project %s — `signet target list --project %s` shows what is attached",
				*ghSecret, *ghRepo, *project, *project)
		}
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return err
		}
		if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
			if err := m.RemoveTarget(t.ID); err != nil {
				return store.AuditRecord{}, err
			}
			return store.AuditRecord{
				Actor: cliActor(), Action: "target.rm", TargetID: t.ID,
				Details:   fmt.Sprintf("%s render (%d keys) → %s detached", *project, len(cfg.Keys), cfg.Destination()),
				EventKind: store.KindTargetConfig, ActorRole: cliRole(),
				Status: &store.AuditStatus{Outcome: store.OutcomeRemoved},
			}, nil
		}); err != nil {
			return err
		}
		fmt.Printf("target removed: %s render → %s\n", *project, cfg.Destination())
		fmt.Printf("the %s %s in %s is left in place — signet just stops updating it\n", cfg.Scope(), cfg.SecretName, cfg.Repo)
		return nil
	}

	if fileMode {
		// Normalized like import's, so the path that registered the target is
		// the path that can detach it — see runTargetAddKey.
		abs, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		t, err := a.st.FindFileTarget(*project, abs)
		if err != nil {
			return err
		}
		if t == nil {
			return fmt.Errorf("no file target %s in project %s", abs, *project)
		}
		cfg, err := t.FileConfig()
		if err != nil {
			return err
		}
		if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
			if err := m.RemoveTarget(t.ID); err != nil {
				return store.AuditRecord{}, err
			}
			return store.AuditRecord{
				Actor: cliActor(), Action: "target.rm", TargetID: t.ID,
				Details:   fmt.Sprintf("%s → %s (%d keys) detached", *project, cfg.Path, len(cfg.Keys)),
				EventKind: store.KindTargetConfig, ActorRole: cliRole(),
				Status: &store.AuditStatus{Outcome: store.OutcomeRemoved},
			}, nil
		}); err != nil {
			return err
		}
		fmt.Printf("target removed: %s → %s\n", *project, cfg.Path)
		fmt.Printf("the file itself is untouched — delete %s by hand if you want it gone\n", cfg.Path)
		return nil
	}

	p, n, err := parseSecretRef(*ref)
	if err != nil {
		return err
	}
	sec, err := a.st.GetSecret(p, n)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret %s/%s", p, n)
	}
	dest := *ghSecret
	if dest == "" {
		dest = n
	}
	t, err := a.st.FindGHTarget(sec.ID, *ghRepo, *ghEnv, dest)
	if err != nil {
		return err
	}
	cfg := store.GHConfig{Repo: *ghRepo, SecretName: dest, Environment: *ghEnv}
	if t == nil {
		return fmt.Errorf("no target %s/%s → %s (%s %s) — `signet target list --secret %s` shows what is attached",
			p, n, *ghRepo, cfg.Scope(), dest, *ref)
	}
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if err := m.RemoveTarget(t.ID); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "target.rm", SecretID: sec.ID, TargetID: t.ID,
			Details:   fmt.Sprintf("%s/%s → %s · %s %s detached", p, n, *ghRepo, cfg.Scope(), dest),
			EventKind: store.KindTargetConfig, ActorRole: cliRole(),
			Status: &store.AuditStatus{Outcome: store.OutcomeRemoved},
		}, nil
	}); err != nil {
		return err
	}
	fmt.Printf("target removed: %s/%s → %s (%s %s)\n", p, n, *ghRepo, cfg.Scope(), dest)
	fmt.Printf("the %s %s in %s is left in place — signet just stops updating it\n", cfg.Scope(), dest, *ghRepo)
	return nil
}

// ---- sync -------------------------------------------------------------------

func runSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	ref := fs.String("secret", "", "only sync this secret (project/NAME)")
	check := fs.Bool("check", false, "preflight every GitHub destination without pushing")
	allowShrink := fs.Bool("allow-shrink", false, "permit a rendered target to deliver fewer keys than its last push")
	fs.Parse(args)
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	var candidates []store.Secret
	if *ref != "" {
		project, name, err := parseSecretRef(*ref)
		if err != nil {
			return err
		}
		sec, err := a.st.GetSecret(project, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("no secret %s/%s", project, name)
		}
		candidates = []store.Secret{*sec}
	} else {
		all, err := a.st.ListSecrets()
		if err != nil {
			return err
		}
		candidates = all
	}
	// Narrowed to secrets that actually have a GitHub destination, so that a run
	// with nothing to push never reaches for the PAT. One read of the target
	// table rather than one query per candidate: this only has to answer "is
	// there a gh-actions destination at all", and PushSecret re-reads each
	// secret's targets below anyway.
	allTargets, err := a.st.ListTargets()
	if err != nil {
		return err
	}
	toSync, err := withGHTargets(a.st, candidates)
	if err != nil {
		return err
	}
	// Rendered targets belong to a project rather than a secret, so they are
	// collected separately. A --secret filter keeps the ones that carry that
	// key: the blob is delivered whole, so syncing one of its keys means
	// delivering the file that contains it.
	renderTargets, err := renderTargetsToSync(a.st, *ref, candidates)
	if err != nil {
		return err
	}
	// A waiver has to name what it waives. --allow-shrink disarms the one guard
	// standing between a shortened key set and a live environment, and as a
	// run-wide switch it disarmed it for every rendered target the run touched
	// — including the ones the operator was not thinking about. Narrowing the
	// run is what makes the waiver specific, so it is required rather than
	// assumed.
	if *allowShrink && len(renderTargets) > 1 {
		return fmt.Errorf("--allow-shrink would disarm the shrink guard for all %d rendered targets in this run, not just the one you mean — narrow it with `--secret <project>/<NAME>`", len(renderTargets))
	}

	if *check {
		gh, err := checkClient(a)
		if err != nil {
			return err
		}
		if err := syncCheck(gh, toSync, allTargets, renderTargets); err != nil {
			return err
		}
		// The grant is only half of what a rendered push needs. Reachability says
		// the credential may write the destination; it says nothing about whether
		// there is a complete blob to write, and a run that passes the first and
		// fails the second is exactly the case --check exists to find before a
		// deploy does. Rendering here costs nothing over the wire.
		return checkRenders(a, renderTargets)
	}

	pushed, failed := 0, 0
	// The credential is resolved inside this guard, not above it: the fallback
	// decrypts the vault's root credential, and doing that for a run with no
	// destinations would record an authentication that never happened.
	if len(toSync) > 0 || len(renderTargets) > 0 {
		tok, err := ops.ResolveGHToken(a.st, a.key, a.cfg.GitHubToken, cliActor(), cliRole())
		if err != nil {
			return err
		}
		noteTokenSource(tok)
		gh := syncpkg.NewGHClient(tok.Value)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for i := range toSync {
			results, err := syncpkg.PushSecret(ctx, a.st, a.key, gh, &toSync[i], cliActor(), cliRole())
			if err != nil {
				return err
			}
			for _, r := range results {
				if r.State == "in sync" {
					pushed++
					fmt.Printf("  ✓ %s/%s → %s (%s)\n", toSync[i].Project, toSync[i].Name, r.Repo, r.Secret)
					if r.Note != "" {
						fmt.Printf("    note: %s\n", r.Note)
					}
				} else {
					failed++
					// The fix leads, because a 403's own prose ("Resource not
					// accessible by personal access token") is true and goes
					// nowhere. It does not stand in for the response: a 403 is also
					// how GitHub answers an archived repo, disabled Actions, and an
					// org SAML or IP policy, and an operator told to edit a PAT
					// that is already correct needs the body to find that out.
					if r.Hint != "" {
						fmt.Printf("  ✗ %s/%s → %s: %s\n", toSync[i].Project, toSync[i].Name, r.Repo, r.Hint)
						fmt.Printf("    GitHub said: %s\n", r.Err)
					} else {
						fmt.Printf("  ✗ %s/%s → %s: %s\n", toSync[i].Project, toSync[i].Name, r.Repo, r.Err)
					}
				}
			}
		}

		// Resolved once per project rather than once per target: the resolve
		// decrypts every secret in the project, and two targets on the same
		// project would pay for that twice to reach the same answer.
		resolved := map[string]map[string]string{}
		for i := range renderTargets {
			t := &renderTargets[i]
			// Resolved leniently and handed to PushRender, which refuses on any
			// gap. The strict view would fail the whole run over a broken secret
			// in the project that this target does not even manage.
			want, cached := resolved[t.Project]
			if !cached {
				v, _, err := a.projectValues(t.Project)
				if err != nil {
					return err
				}
				resolved[t.Project] = v
				want = v
			}
			res, err := syncpkg.PushRender(ctx, a.st, a.key, gh, t, want,
				syncpkg.RenderPushOptions{AllowShrink: *allowShrink}, cliActor(), cliRole())
			if err != nil {
				return err
			}
			if res.State == "in sync" {
				pushed++
				fmt.Printf("  ✓ %s render → %s\n", t.Project, res.Dest)
				if res.Note != "" {
					fmt.Printf("    note: %s\n", res.Note)
				}
				continue
			}
			failed++
			if res.Hint != "" {
				fmt.Printf("  ✗ %s render → %s: %s\n", t.Project, res.Dest, res.Hint)
				fmt.Printf("    GitHub said: %s\n", res.Err)
			} else {
				fmt.Printf("  ✗ %s render → %s: %s\n", t.Project, res.Dest, res.Err)
			}
		}
	}
	fmt.Printf("sync complete: %d pushed, %d failed\n", pushed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
}

// renderTargetsToSync selects the rendered targets a run covers. An unfiltered
// run takes them all; a --secret filter keeps those whose key set contains that
// secret, because the only way to sync one key of a blob is to deliver the
// blob.
func renderTargetsToSync(st *store.Store, ref string, candidates []store.Secret) ([]store.Target, error) {
	all, err := st.RenderTargets()
	if err != nil {
		return nil, err
	}
	if ref == "" {
		return all, nil
	}
	// One candidate, because a --secret filter is what put us here.
	sec := candidates[0]
	var out []store.Target
	for _, t := range all {
		if t.Project != sec.Project {
			continue
		}
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return nil, err
		}
		if cfg.Manages(sec.Name) {
			out = append(out, t)
		}
	}
	return out, nil
}

// checkRenders answers, for every rendered target a run covers, whether there
// is actually a blob to deliver — the half of the question syncCheck cannot ask
// because reachability is a property of the credential and completeness is a
// property of the vault.
//
// It reports every failing target rather than stopping at the first: an
// operator checking before a deploy wants the whole list, and refusing one at a
// time turns a single fix into as many runs as there are gaps.
func checkRenders(a *app, renderTargets []store.Target) error {
	resolved := map[string]map[string]string{}
	var refused int
	for i := range renderTargets {
		t := &renderTargets[i]
		want, cached := resolved[t.Project]
		if !cached {
			v, _, err := a.projectValues(t.Project)
			if err != nil {
				return err
			}
			resolved[t.Project] = v
			want = v
		}
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return err
		}
		if _, rerr := syncpkg.RenderBlob(cfg, t.Project, want); rerr != nil {
			refused++
			fmt.Printf("  ✗ %s render → %s: %s\n", t.Project, cfg.Destination(), rerr)
			continue
		}
		fmt.Printf("  ✓ %s render → %s (%d keys) would deliver\n", t.Project, cfg.Destination(), len(cfg.Keys))
	}
	if refused > 0 {
		return fmt.Errorf("%d rendered target(s) would be refused by `signet sync` — the destination is reachable, the render is not complete", refused)
	}
	return nil
}

// checkClient resolves the credential `sync --check` probes with. Unlike the
// add-time preflight, a missing credential fails the command: a check that
// silently checked nothing would report success.
func checkClient(a *app) (*syncpkg.GHClient, error) {
	tok, err := ops.ResolveGHTokenFor(a.st, a.key, a.cfg.GitHubToken, cliActor(), cliRole(), ops.PurposePreflight)
	if err != nil {
		return nil, err
	}
	noteTokenSource(tok)
	return syncpkg.NewGHClient(tok.Value), nil
}

// syncCheck answers, without pushing anything, the question a sync would
// otherwise answer one secret at a time and only after sealing each value: can
// this credential reach every repository signet is expected to write to.
//
// It probes per repository rather than per target, because the grant is per
// repository — twelve secrets bound for one repo share one answer, and asking
// twelve times would spend twelve API calls to learn it.
//
// Failure comes back as an error rather than an os.Exit so that the caller's
// deferred close still runs on a vault this command has just written a
// secret_reveal to, and so the whole thing can be driven from a test.
func syncCheck(gh *syncpkg.GHClient, toSync []store.Secret, allTargets []store.Target, renderTargets []store.Target) error {
	wanted := map[string]bool{}
	for i := range toSync {
		wanted[toSync[i].ID] = true
	}
	// Keyed by repository *and* environment, because that pair is what the
	// grant is checked against: an environment has its own sealing key behind
	// its own path, so a repository that answers cannot vouch for an
	// environment inside it, and collapsing the two would report a destination
	// as reachable on the strength of a probe that never touched it.
	counts := map[ghDest]int{}
	for _, t := range allTargets {
		if t.Kind != "gh-actions" || !wanted[t.SecretID] {
			continue
		}
		cfg, err := t.GHConfig()
		if err != nil {
			return err
		}
		counts[ghDest{cfg.Repo, cfg.Environment}]++
	}
	for _, t := range renderTargets {
		cfg, err := t.GHRenderConfig()
		if err != nil {
			return err
		}
		counts[ghDest{cfg.Repo, cfg.Environment}]++
	}
	if len(counts) == 0 {
		fmt.Println("no GitHub destinations to check")
		return nil
	}
	dests := make([]ghDest, 0, len(counts))
	for d := range counts {
		dests = append(dests, d)
	}
	sort.Slice(dests, func(i, j int) bool {
		if dests[i].repo != dests[j].repo {
			return dests[i].repo < dests[j].repo
		}
		return dests[i].env < dests[j].env
	})

	// Blocked and inconclusive are counted apart, because they mean opposite
	// things: one is a destination that will fail until a person fixes it, the
	// other is a question GitHub declined to answer just now. Failing the run on
	// the second would turn a rate limit into a report of misconfigured grants.
	var blocked, unknown int
	for _, d := range dests {
		probe := probeRepo(gh, d.repo, d.env)
		// A refused credential is the answer for every remaining destination,
		// and it is not about any of them — which is why the message
		// deliberately names none, and why nothing is appended here that would.
		if probe.Access == syncpkg.AccessRejected {
			return fmt.Errorf("%s (stopped before checking the remaining destinations — they would answer the same)", probe.Message())
		}
		plural := "secrets"
		if counts[d] == 1 {
			plural = "secret"
		}
		switch {
		// A read that passed while the write probe was rate-limited or 5xx'd is
		// not a green destination: the half that decides whether a push lands is
		// exactly the half that went unanswered. Counted as inconclusive rather
		// than reachable, which is the distinction this whole check exists to
		// keep.
		case probe.Access == syncpkg.AccessOK && probe.Write == syncpkg.WriteUnknown:
			unknown++
			fmt.Printf("  ? %s (%d %s): readable, but the write check did not settle: %s\n", d, counts[d], plural, probe.Message())
		case probe.Access == syncpkg.AccessOK:
			fmt.Printf("  ✓ %s (%d %s)\n", d, counts[d], plural)
			// A pass can still carry something the operator must hear — the write
			// probe issuing a delete that was not a no-op. Printing only the tick
			// is what made that report vanish.
			if msg := probe.Message(); msg != "" {
				fmt.Printf("    warning: %s\n", msg)
			}
		case probe.Blocked():
			blocked++
			fmt.Printf("  ✗ %s (%d %s): %s\n", d, counts[d], plural, probe.Message())
		default:
			unknown++
			fmt.Printf("  ? %s (%d %s): %s\n", d, counts[d], plural, probe.Message())
		}
	}

	summary := fmt.Sprintf("preflight complete: %d of %d destinations reachable", len(dests)-blocked-unknown, len(dests))
	if unknown > 0 {
		summary += fmt.Sprintf(", %d inconclusive", unknown)
	}
	fmt.Println(summary)
	// Only positive evidence fails the run. An inconclusive probe is reported
	// and left at that: it says nothing about the grant, so failing on it would
	// make an unrelated GitHub hiccup indistinguishable from a real problem.
	if blocked > 0 {
		return fmt.Errorf("%d of %d destinations are unreachable — sync would fail against them", blocked, len(dests))
	}
	return nil
}

// ghDest is one probed destination: a repository, or an environment within one.
type ghDest struct {
	repo string
	env  string
}

func (d ghDest) String() string {
	if d.env == "" {
		return d.repo
	}
	return d.repo + " · " + d.env
}

// probeRepo runs one preflight under its own deadline, so a destination that
// hangs costs its own timeout rather than the rest of the run's.
func probeRepo(gh *syncpkg.GHClient, repo, env string) syncpkg.RepoProbe {
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	return gh.CheckRepoAccess(ctx, repo, env)
}

// ---- status -----------------------------------------------------------------

func runStatus(args []string) error {
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	secrets, err := a.st.ListSecrets()
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		fmt.Println("vault is empty — `signet import` or `signet set` to add secrets")
		return nil
	}

	// Pre-compute file drift per project.
	projects := map[string]bool{}
	for _, s := range secrets {
		projects[s.Project] = true
	}
	type fileInfo struct {
		cfg   store.FileConfig
		drift syncpkg.FileDrift
	}
	type renderInfo struct {
		cfg   store.GHRenderConfig
		state string
	}
	fileByProject := map[string][]fileInfo{}
	renderByProject := map[string][]renderInfo{}
	for p := range projects {
		// Lenient: status is the view an operator reaches for when something is
		// wrong, so one unresolvable derivation must not take the whole listing
		// down — least of all the row describing the broken entry.
		want, _, err := a.projectValues(p)
		if err != nil {
			return err
		}
		fts, err := a.st.FileTargetsForProject(p)
		if err != nil {
			return err
		}
		for _, ft := range fts {
			cfg, err := ft.FileConfig()
			if err != nil {
				return err
			}
			fileByProject[p] = append(fileByProject[p], fileInfo{cfg, syncpkg.CheckFile(cfg.Path, want, cfg.Keys)})
		}
		rts, err := a.st.RenderTargetsForProject(p)
		if err != nil {
			return err
		}
		for i := range rts {
			cfg, err := rts[i].GHRenderConfig()
			if err != nil {
				return err
			}
			renderByProject[p] = append(renderByProject[p], renderInfo{cfg, renderState(&rts[i], cfg, want, a.key)})
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROJECT\tSECRET\tVHASH\tSTATUS\tEXPIRES\tTARGETS")
	for _, sec := range secrets {
		cur, digest, derr := a.ghDrift(&sec)
		// A derived secret shows what it is composed from where a stored one
		// shows its version hash. It has no version — and after a --replace
		// conversion the abandoned rows it still owns would print a hash for a
		// value nothing reads, presenting a computed secret as an ordinary one
		// with a current stored value.
		vhash := "-"
		switch {
		case sec.Derived() && derr != nil:
			vhash = "derived (unresolved)"
		case sec.Derived():
			vhash = "derived #" + digest
		case cur != nil:
			vhash = "#" + cur.VHash
		}
		expires := "-"
		if s := expiresIn(sec.ExpiresAt); s != "" {
			expires = s
		}
		var tgt []string
		ghTargets, err := a.st.TargetsForSecret(sec.ID)
		if err != nil {
			return err
		}
		for _, t := range ghTargets {
			cfg, err := t.GHConfig()
			if err != nil {
				return err
			}
			ghState := t.GHState(cur, digest)
			if derr != nil {
				ghState = "unresolved"
			}
			tgt = append(tgt, fmt.Sprintf("gh:%s→%s [%s]", cfg.Repo+dotted(cfg.Environment), cfg.SecretName, ghState))
		}
		// A rendered target is delivered whole, so it annotates every secret it
		// carries with the same state — the blob is current or it is not, and no
		// key inside it can be current on its own.
		for _, ri := range renderByProject[sec.Project] {
			if !ri.cfg.Manages(sec.Name) {
				continue
			}
			tgt = append(tgt, fmt.Sprintf("gh-render:%s→%s [%s]", ri.cfg.Repo+dotted(ri.cfg.Environment), ri.cfg.SecretName, ri.state))
		}
		for _, fi := range fileByProject[sec.Project] {
			if !fi.cfg.Manages(sec.Name) {
				continue
			}
			// Shared with `target list` rather than recomputed: this had its own
			// copy of the reduction, which meant a state added to FileDrift was
			// reported by one view and silently read as "in sync" by the other.
			tgt = append(tgt, fmt.Sprintf("file:%s [%s]", fi.cfg.Path, fileState(fi.drift, sec.Name)))
		}
		if len(tgt) == 0 {
			tgt = []string{"-"}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", sec.Project, sec.Name, vhash, sec.Status, expires, strings.Join(tgt, ", "))
	}
	return w.Flush()
}

// expiresIn renders an RFC3339 expiry as "2026-10-19 (79d)", or "" when there
// is none to render. Shared by `status` and sync's fallback notice so the two
// cannot disagree about when a credential dies.
func expiresIn(expiresAt string) string {
	if expiresAt == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), int(time.Until(t).Hours()/24))
}

// dotted renders an optional environment as a suffix, so status's compact
// target notation can carry the scope without a separate column.
func dotted(env string) string {
	if env == "" {
		return ""
	}
	return "·" + env
}

// ---- audit ------------------------------------------------------------------

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// auditOutcome renders an entry's structured outcome, annotated with the
// transport detail when one was measured: "delivered 204 · 84ms".
func auditOutcome(e store.AuditEntry) string {
	if e.Status == nil {
		return "-"
	}
	out := string(e.Status.Outcome)
	if e.Status.HTTPStatus != nil {
		out += fmt.Sprintf(" %d", *e.Status.HTTPStatus)
	}
	if e.Status.LatencyMS != nil {
		out += fmt.Sprintf(" · %dms", *e.Status.LatencyMS)
	}
	return out
}

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	ref := fs.String("secret", "", "filter to one secret (project/NAME)")
	verify := fs.Bool("verify", false, "verify the whole hash chain")
	limit := fs.Int("limit", 50, "entries to show")
	fs.Parse(args)
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

	if *verify {
		ok, badSeq, total, err := a.st.VerifyAudit()
		if err != nil {
			return err
		}
		if ok {
			fmt.Printf("chain verified · %d entries intact\n", total)
		} else {
			fmt.Printf("CHAIN BROKEN at seq %d (%d entries walked)\n", badSeq, total)
			os.Exit(1)
		}
	}

	secretID := ""
	if *ref != "" {
		project, name, err := parseSecretRef(*ref)
		if err != nil {
			return err
		}
		sec, err := a.st.GetSecret(project, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("no secret %s/%s", project, name)
		}
		secretID = sec.ID
	}
	entries, err := a.st.ListAudit(*limit, secretID)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tTS\tACTOR\tROLE\tACTION\tKIND\tOUTCOME\tDETAILS\tHASH")
	for _, e := range entries {
		details := e.Details
		if len(details) > 60 {
			details = details[:57] + "…"
		}
		// Entries predating the structured ledger carry none of these; show a
		// dash rather than an empty column so absent reads as absent.
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s…\n",
			e.Seq, e.TS, e.Actor, dashIfEmpty(string(e.ActorRole)), e.Action,
			dashIfEmpty(string(e.EventKind)), auditOutcome(e), details, e.Hash[:6])
	}
	return w.Flush()
}

// ---- serve ------------------------------------------------------------------

func runServe() error {
	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	var gh *syncpkg.GHClient
	if a.cfg.GitHubToken != "" {
		gh = syncpkg.NewGHClient(a.cfg.GitHubToken)
	}
	srv, err := api.New(a.st, a.key, gh, a.cfg.APIToken)
	if err != nil {
		return err
	}
	ctx, stop := signalContext(os.Interrupt, syscall.SIGTERM)
	defer stop()
	return api.Serve(ctx, a.cfg.Addrs, srv)
}

// signalContext returns a context cancelled by the first of sigs to arrive,
// having logged which one it was on the way.
//
// signal.NotifyContext knows the same fact and does not throw it away: it
// cancels with a cause, and context.Cause reports "terminated signal received".
// Two things make it worth hand-rolling anyway, and neither is that the
// standard library loses the signal.
//
// The cause is only readable once Serve has returned, which puts the line after
// the shutdown it explains — "api stopped", then "received SIGTERM", in that
// order. Logging on arrival keeps the journal in the order the events actually
// happened: listening, received, stopped.
//
// And a cause spells the signal the way Signal.String does, as "terminated".
// Whoever reads this line is working out what stopped the vault, and will be
// searching for SIGTERM.
//
// Why the line has to exist at all: the daemon twice ended with nothing in the
// journal but systemd's "Deactivated successfully" and status=0/SUCCESS, days
// apart, staying down until someone noticed by hand — a record that cannot
// distinguish being told to stop from stopping on its own. It can only be the
// former: main sends every non-nil error to log.Fatal, so any failure exits 1
// and says why, and a listener that dies on its own returns non-nil. A silent
// exit 0 is reachable only through this context being cancelled. Because
// systemd announces its own stops as "Stopping signet.service...", a line here
// with no such announcement above it is an outside sender by elimination.
func signalContext(sigs ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	// Buffered so the notify runtime never blocks handing the signal over, and
	// stopped by the returned func so the goroutine cannot outlive the caller.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	go func() {
		select {
		case sig := <-ch:
			log.Printf("received %s — shutting down", signalName(sig))
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}

// signalName prefers the mnemonic over what Signal.String reports, because the
// journal line is read by whoever is working out who stopped the vault and
// "terminated" is not what they will be grepping for.
func signalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case os.Interrupt:
		return "SIGINT"
	}
	return sig.String()
}
