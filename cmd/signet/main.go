// Command signet is the construct-server credential vault and outbound-sync
// control plane (IDEA-13, first slice): a host-resident single static binary
// that is both a CLI and a thin HTTP API.
//
//	signet init                                    # create master key + database
//	signet import --project lyceum ~/projects/lyceum/.env
//	signet set --project csrv --name API_TOKEN --generate
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

	var err error
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
	fmt.Fprintln(w, "commands: init, import, set, derive, reveal, render, target, sync, status, audit, serve, version")
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

// cliActor identifies the invoking human in audit entries.
func cliActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
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
		EventKind: store.KindVaultInit, ActorRole: store.RoleHuman,
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

	res, err := ops.ImportEnv(a.st, a.key, *project, *scope, path, cliActor(), store.RoleHuman)
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

func runSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	name := fs.String("name", "", "secret name (required)")
	scope := fs.String("scope", "", "scope")
	generate := fs.Bool("generate", false, "generate a random 32-char value instead of reading stdin")
	expires := fs.String("expires", "", "expiry date YYYY-MM-DD")
	fs.Parse(args)
	if *project == "" || *name == "" {
		return fmt.Errorf("usage: signet set --project <p> --name <N> [--scope s] [--generate] [--expires YYYY-MM-DD]")
	}
	expiresAt := ""
	if *expires != "" {
		t, err := time.Parse("2006-01-02", *expires)
		if err != nil {
			return fmt.Errorf("--expires: %w", err)
		}
		expiresAt = t.UTC().Format(time.RFC3339)
	}
	// Whether the flag was given at all, which is not the same question as
	// whether it carries a date: absent means "leave the expiry alone", and an
	// explicit --expires "" means "clear it", matching the API's set-expiry.
	expiresGiven := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expires" {
			expiresGiven = true
		}
	})

	var value string
	if *generate {
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

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()
	sec, err := a.st.GetSecret(*project, *name)
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
			*project, *name, sec.Derivation)
	}
	nonce, ct, err := vault.Encrypt(a.key, []byte(value))
	if err != nil {
		return err
	}

	// Anything composed from this secret changes the moment this write lands,
	// and is rewritten by the next render. Saying so before the write is the
	// difference between a rotation and a rotation plus four surprises — the
	// motivating case spans projects, so the operator has no reason to be
	// looking at the affected files.
	dependents, err := resolve.Dependents(a.st, *project, *name)
	if err != nil {
		return err
	}
	// On an existing secret the expiry is a second change riding along with the
	// value, and it used to be read off the command line and dropped — `set
	// --expires` moved the value and left the old date in place. Rotating a
	// credential is exactly when both move together, and the failure was silent:
	// the command printed the new version and said nothing about the expiry it
	// had not written. Derived here, from the secret as read, so nothing has to
	// escape the transaction through a captured variable.
	setExpiry := expiresGiven && sec != nil && expiresAt != sec.ExpiresAt
	expiryNote := ""
	if setExpiry {
		expiryNote = " · expiry cleared"
		if expiresAt != "" {
			expiryNote = " · expiry set to " + *expires
		}
	}
	// Creating the secret, writing the version and recording it are one
	// transaction: a half-created secret with no version, or a value that landed
	// with nothing in the ledger to say so, are both worse than the write simply
	// failing. The expiry joins them for the same reason — a rotation that half
	// landed is the state this is meant to prevent.
	v, _, err := store.MutateValue(a.st, func(m *store.Mutation) (*store.Version, store.AuditRecord, error) {
		target, action, outcome := sec, "secret.update", store.OutcomeUpdated
		if target == nil {
			created, err := m.CreateSecret(*project, *name, *scope, *generate, expiresAt)
			if err != nil {
				return nil, store.AuditRecord{}, err
			}
			target, action, outcome = created, "secret.create", store.OutcomeCreated
		} else if setExpiry {
			if err := m.SetExpiry(target.ID, expiresAt); err != nil {
				return nil, store.AuditRecord{}, err
			}
		}
		ver, err := m.AddVersion(target.ID, nonce, ct, vault.VersionHash(nonce, ct), cliActor())
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		// One entry, because it was one transaction. The version write is the
		// event; the expiry rides in its details rather than becoming a second
		// entry that could only ever be appended after the first had committed.
		return ver, store.AuditRecord{
			Actor: cliActor(), Action: action, SecretID: target.ID,
			Details:   fmt.Sprintf("%s/%s · version %d #%s%s", *project, *name, ver.VersionNo, ver.VHash, expiryNote),
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s → version %d #%s%s\n", *project, *name, v.VersionNo, v.VHash, expiryNote)
	reportDependents(dependents, *project, *name)
	warnUndelivered(a, *project, *name)
	return nil
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
	if err != nil || len(targets) == 0 {
		return // no rendered file for this project — nothing to be wrong about
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
		if contains(cfg.Keys, name) {
			return
		}
		paths = append(paths, cfg.Path)
	}
	fmt.Fprintf(os.Stderr, "warning: no file target for %s manages %s — render will not write it to %s\n",
		project, name, strings.Join(paths, ", "))
	fmt.Fprintf(os.Stderr, "  add it with: signet target add-key --project %s --path %s --name %s\n",
		project, paths[0], name)
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
		EventKind: store.KindSecretReveal, ActorRole: store.RoleHuman,
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
			EventKind: store.KindSecretReveal, ActorRole: store.RoleHuman,
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
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
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
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
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
	fs.Parse(args)
	if *project == "" {
		return fmt.Errorf("usage: signet render --project <p> [--check] [--prune]")
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
	if len(targets) == 0 {
		return fmt.Errorf("project %s has no file targets (import an env file first)", *project)
	}
	want, err := a.projectValuesStrict(*project)
	if err != nil {
		return err
	}

	for _, t := range targets {
		cfg, err := t.FileConfig()
		if err != nil {
			return err
		}
		if *check {
			// --check --prune is the dry run for a delete that cannot be undone,
			// so it is answered rather than rejected: same report, framed as what
			// --prune would take.
			printDrift(syncpkg.CheckFile(cfg.Path, want, cfg.Keys), *prune)
			continue
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
			EventKind: store.KindRender, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
		}); err != nil {
			return err
		}
		fmt.Printf("rendered %s (%d keys%s)\n", cfg.Path, len(pairs), note)
	}
	return nil
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

// printDrift reports one file target's state. With prune set the report is the
// dry run for `render --prune`, so the unmanaged keys are framed as what that
// write would delete rather than what an ordinary one would keep.
func printDrift(d syncpkg.FileDrift, prune bool) {
	switch {
	case d.MissingFile:
		fmt.Printf("%s: MISSING FILE\n", d.Path)
		return
	case d.Unreadable != "":
		fmt.Printf("%s: UNREADABLE — render will refuse this file rather than overwrite it\n", d.Path)
		fmt.Printf("  %s\n", d.Unreadable)
		return
	case d.Clean():
		fmt.Printf("%s: in sync (%d keys)\n", d.Path, len(d.Keys))
	default:
		fmt.Printf("%s: DRIFT\n", d.Path)
		for _, k := range d.Keys {
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
  signet target add --secret <p>/<NAME> --gh-repo owner/name [--gh-secret NAME] [--no-preflight]
  signet target add-key --project <p> --path </path/to/.env> --name NAME[,NAME…]
  signet target rm  --secret <p>/<NAME> --gh-repo owner/name [--gh-secret NAME]
  signet target rm  --project <p> --path </path/to/.env>`

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
	path := fs.String("path", "", "rendered file path (required)")
	name := fs.String("name", "", "secret name(s) to add, comma-separated (required)")
	fs.Parse(args)
	if *project == "" || *path == "" || *name == "" {
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
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
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

func runTargetAdd(args []string) error {
	fs := flag.NewFlagSet("target add", flag.ExitOnError)
	ref := fs.String("secret", "", "secret ref project/NAME (required)")
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (required)")
	ghSecret := fs.String("gh-secret", "", "destination Actions secret name (default: local name)")
	noPreflight := fs.Bool("no-preflight", false, "skip the check that the PAT can reach the repo")
	fs.Parse(args)
	if *ref == "" || *ghRepo == "" || !strings.Contains(*ghRepo, "/") {
		return fmt.Errorf("%s", targetUsage)
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
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		// Checked inside the transaction that inserts, so the destination
		// cannot appear between the check and the write. The API refuses the
		// same duplicate; without this the CLI would quietly attach a second
		// target pushing the same value to the same place.
		dup, err := m.FindGHTarget(sec.ID, *ghRepo, dest)
		if err != nil {
			return store.AuditRecord{}, err
		}
		if dup != nil {
			return store.AuditRecord{}, fmt.Errorf("target already exists: %s/%s → %s (Actions secret %s)", project, name, *ghRepo, dest)
		}
		t, err := m.AddGHTarget(sec.ID, *ghRepo, dest)
		if err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "target.add", SecretID: sec.ID, TargetID: t.ID,
			Details:   fmt.Sprintf("%s/%s → %s · Actions secret %s", project, name, *ghRepo, dest),
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	}); err != nil {
		return err
	}
	fmt.Printf("target added: %s/%s → %s (Actions secret %s)\n", project, name, *ghRepo, dest)
	// The add stands either way. A grant that is not in place yet is a normal
	// order of operations — attach the destination, then widen the PAT — and
	// refusing here would make the two commands depend on each other's order for
	// no reason. What is worth changing is when the operator finds out: at the
	// add, not at the next push of an unrelated secret. Skipping the check is
	// not the same as failing it, so --no-preflight leaves the path clear.
	clear := true
	if !*noPreflight {
		clear = preflightGHRepo(preflightClient(a), *ghRepo)
	}
	if clear {
		fmt.Println("run `signet sync` to push")
	}
	return nil
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
	tok, err := ops.ResolveGHTokenFor(a.st, a.key, a.cfg.GitHubToken, cliActor(), store.RoleHuman, ops.PurposePreflight)
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
func preflightGHRepo(gh *syncpkg.GHClient, repo string) bool {
	if gh == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	probe := gh.CheckRepoAccess(ctx, repo)
	if probe.Access == syncpkg.AccessOK {
		return true
	}
	// Reported whether or not signet can attribute it: a probe that failed for a
	// reason signet has no name for is still something the operator asked for
	// and did not get.
	fmt.Fprintf(os.Stderr, "warning: %s\n", probe.Message())
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
			emit(sec.Project+"/"+sec.Name, t.Kind, cfg.Repo+" · "+cfg.SecretName, state, t.LastPushedAt)

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
			if wantSecret != nil && !contains(cfg.Keys, wantSecret.Name) {
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
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (gh targets)")
	ghSecret := fs.String("gh-secret", "", "destination Actions secret name (default: local name)")
	project := fs.String("project", "", "project (file targets)")
	path := fs.String("path", "", "rendered file path (file targets)")
	fs.Parse(args)

	ghMode := *ref != "" || *ghRepo != ""
	fileMode := *project != "" || *path != ""
	switch {
	case ghMode && fileMode:
		return fmt.Errorf("choose one: --secret/--gh-repo for a GitHub target, or --project/--path for a file target")
	case ghMode && (*ref == "" || *ghRepo == ""):
		return fmt.Errorf("%s", targetUsage)
	case fileMode && (*project == "" || *path == ""):
		return fmt.Errorf("%s", targetUsage)
	case !ghMode && !fileMode:
		return fmt.Errorf("%s", targetUsage)
	}

	a, err := setup()
	if err != nil {
		return err
	}
	defer a.close()

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
				EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
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
	t, err := a.st.FindGHTarget(sec.ID, *ghRepo, dest)
	if err != nil {
		return err
	}
	if t == nil {
		return fmt.Errorf("no target %s/%s → %s (Actions secret %s) — `signet target list --secret %s` shows what is attached",
			p, n, *ghRepo, dest, *ref)
	}
	if _, err := a.st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if err := m.RemoveTarget(t.ID); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{
			Actor: cliActor(), Action: "target.rm", SecretID: sec.ID, TargetID: t.ID,
			Details:   fmt.Sprintf("%s/%s → %s · Actions secret %s detached", p, n, *ghRepo, dest),
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeRemoved},
		}, nil
	}); err != nil {
		return err
	}
	fmt.Printf("target removed: %s/%s → %s (Actions secret %s)\n", p, n, *ghRepo, dest)
	fmt.Printf("the Actions secret %s in %s is left in place — signet just stops updating it\n", dest, *ghRepo)
	return nil
}

// ---- sync -------------------------------------------------------------------

func runSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	ref := fs.String("secret", "", "only sync this secret (project/NAME)")
	check := fs.Bool("check", false, "preflight every GitHub destination without pushing")
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
	hasGH := map[string]bool{}
	allTargets, err := a.st.ListTargets()
	if err != nil {
		return err
	}
	for _, t := range allTargets {
		if t.Kind == "gh-actions" {
			hasGH[t.SecretID] = true
		}
	}
	var toSync []store.Secret
	for _, sec := range candidates {
		if hasGH[sec.ID] {
			toSync = append(toSync, sec)
		}
	}

	if *check {
		gh, err := checkClient(a)
		if err != nil {
			return err
		}
		return syncCheck(gh, toSync, allTargets)
	}

	pushed, failed := 0, 0
	// The credential is resolved inside this guard, not above it: the fallback
	// decrypts the vault's root credential, and doing that for a run with no
	// destinations would record an authentication that never happened.
	if len(toSync) > 0 {
		tok, err := ops.ResolveGHToken(a.st, a.key, a.cfg.GitHubToken, cliActor(), store.RoleHuman)
		if err != nil {
			return err
		}
		noteTokenSource(tok)
		gh := syncpkg.NewGHClient(tok.Value)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for i := range toSync {
			results, err := syncpkg.PushSecret(ctx, a.st, a.key, gh, &toSync[i], cliActor(), store.RoleHuman)
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
	}
	fmt.Printf("sync complete: %d pushed, %d failed\n", pushed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
}

// checkClient resolves the credential `sync --check` probes with. Unlike the
// add-time preflight, a missing credential fails the command: a check that
// silently checked nothing would report success.
func checkClient(a *app) (*syncpkg.GHClient, error) {
	tok, err := ops.ResolveGHTokenFor(a.st, a.key, a.cfg.GitHubToken, cliActor(), store.RoleHuman, ops.PurposePreflight)
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
func syncCheck(gh *syncpkg.GHClient, toSync []store.Secret, allTargets []store.Target) error {
	wanted := map[string]bool{}
	for i := range toSync {
		wanted[toSync[i].ID] = true
	}
	counts := map[string]int{}
	for _, t := range allTargets {
		if t.Kind != "gh-actions" || !wanted[t.SecretID] {
			continue
		}
		cfg, err := t.GHConfig()
		if err != nil {
			return err
		}
		counts[cfg.Repo]++
	}
	if len(counts) == 0 {
		fmt.Println("no GitHub destinations to check")
		return nil
	}
	repos := make([]string, 0, len(counts))
	for repo := range counts {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	// Blocked and inconclusive are counted apart, because they mean opposite
	// things: one is a destination that will fail until a person fixes it, the
	// other is a question GitHub declined to answer just now. Failing the run on
	// the second would turn a rate limit into a report of misconfigured grants.
	var blocked, unknown int
	for _, repo := range repos {
		probe := probeRepo(gh, repo)
		// A refused credential is the answer for every remaining repository, and
		// it is not about any of them — which is why the message deliberately
		// names no repo, and why nothing is appended here that would.
		if probe.Access == syncpkg.AccessRejected {
			return fmt.Errorf("%s (stopped before checking the remaining repositories — they would answer the same)", probe.Message())
		}
		plural := "secrets"
		if counts[repo] == 1 {
			plural = "secret"
		}
		switch {
		case probe.Access == syncpkg.AccessOK:
			fmt.Printf("  ✓ %s (%d %s)\n", repo, counts[repo], plural)
		case probe.Blocked():
			blocked++
			fmt.Printf("  ✗ %s (%d %s): %s\n", repo, counts[repo], plural, probe.Message())
		default:
			unknown++
			fmt.Printf("  ? %s (%d %s): %s\n", repo, counts[repo], plural, probe.Message())
		}
	}

	summary := fmt.Sprintf("preflight complete: %d of %d repositories reachable", len(repos)-blocked-unknown, len(repos))
	if unknown > 0 {
		summary += fmt.Sprintf(", %d inconclusive", unknown)
	}
	fmt.Println(summary)
	// Only positive evidence fails the run. An inconclusive probe is reported
	// and left at that: it says nothing about the grant, so failing on it would
	// make an unrelated GitHub hiccup indistinguishable from a real problem.
	if blocked > 0 {
		return fmt.Errorf("%d of %d repositories are unreachable — sync would fail against them", blocked, len(repos))
	}
	return nil
}

// probeRepo runs one preflight under its own deadline, so a repository that
// hangs costs its own timeout rather than the rest of the run's.
func probeRepo(gh *syncpkg.GHClient, repo string) syncpkg.RepoProbe {
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	return gh.CheckRepoAccess(ctx, repo)
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
	fileByProject := map[string][]fileInfo{}
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
			tgt = append(tgt, fmt.Sprintf("gh:%s→%s [%s]", cfg.Repo, cfg.SecretName, ghState))
		}
		for _, fi := range fileByProject[sec.Project] {
			if !contains(fi.cfg.Keys, sec.Name) {
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

func contains(xs []string, s string) bool {
	i := sort.SearchStrings(xs, s)
	return i < len(xs) && xs[i] == s
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
