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
//	signet sync [--secret csrv/RELEASE_BOT_PRIVATE_KEY]
//	signet status
//	signet audit [--secret csrv/NAME] [--verify]
//	signet serve                                   # HTTP API for the Switchyard mirror
//	signet version
package main

import (
	"bufio"
	"context"
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
	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/ops"
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
	fmt.Fprintln(w, "commands: init, import, set, reveal, render, target, sync, status, audit, serve, version")
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
	nonce, ct, err := vault.Encrypt(a.key, []byte(value))
	if err != nil {
		return err
	}
	// Creating the secret, writing the version and recording it are one
	// transaction: a half-created secret with no version, or a value that landed
	// with nothing in the ledger to say so, are both worse than the write simply
	// failing.
	v, _, err := store.MutateValue(a.st, func(m *store.Mutation) (*store.Version, store.AuditRecord, error) {
		target, action, outcome := sec, "secret.update", store.OutcomeUpdated
		if target == nil {
			created, err := m.CreateSecret(*project, *name, *scope, *generate, expiresAt)
			if err != nil {
				return nil, store.AuditRecord{}, err
			}
			target, action, outcome = created, "secret.create", store.OutcomeCreated
		}
		ver, err := m.AddVersion(target.ID, nonce, ct, vault.VersionHash(nonce, ct), cliActor())
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		return ver, store.AuditRecord{
			Actor: cliActor(), Action: action, SecretID: target.ID,
			Details:   fmt.Sprintf("%s/%s · version %d #%s", *project, *name, ver.VersionNo, ver.VHash),
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: outcome},
		}, nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%s → version %d #%s\n", *project, *name, v.VersionNo, v.VHash)
	warnUndelivered(a, *project, *name)
	return nil
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
	cur, err := a.st.CurrentVersion(sec.ID)
	if err != nil {
		return err
	}
	if cur == nil {
		return fmt.Errorf("%s/%s has no versions", *project, *name)
	}
	plain, err := vault.Decrypt(a.key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return err
	}
	if _, err := a.st.AppendAudit(store.AuditRecord{
		Actor: cliActor(), Action: "secret.reveal", SecretID: sec.ID,
		Details:   fmt.Sprintf("revealed %s/%s version %d #%s to stdout", *project, *name, cur.VersionNo, cur.VHash),
		EventKind: store.KindSecretReveal, ActorRole: store.RoleHuman,
		Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
	}); err != nil {
		return err
	}
	fmt.Println(string(plain))
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
	want, err := a.projectValues(*project)
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
		if err := a.st.UpdateTargetPush(t.ID, "in sync", "", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
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

// projectValues decrypts every current value of a project into a map.
func (a *app) projectValues(project string) (map[string]string, error) {
	secrets, err := a.st.ListSecrets()
	if err != nil {
		return nil, err
	}
	want := map[string]string{}
	for _, sec := range secrets {
		if sec.Project != project {
			continue
		}
		cur, err := a.st.CurrentVersion(sec.ID)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			continue
		}
		plain, err := vault.Decrypt(a.key, cur.Nonce, cur.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", project, sec.Name, err)
		}
		want[sec.Name] = string(plain)
	}
	return want, nil
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
  signet target add --secret <p>/<NAME> --gh-repo owner/name [--gh-secret NAME]
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
	fmt.Println("run `signet sync` to push")
	return nil
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
		v, err := a.projectValues(project)
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
			// Needs the secret's current version: "in sync" from the last push
			// is not the same as "still current".
			cur, err := a.st.CurrentVersion(sec.ID)
			if err != nil {
				return err
			}
			emit(sec.Project+"/"+sec.Name, t.Kind, cfg.Repo+" · "+cfg.SecretName, t.GHState(cur), t.LastPushedAt)

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
	// Narrowed to secrets that actually have a GitHub destination — file targets
	// are project-scoped and never answer here — so that a run with nothing to
	// push does not reach for the PAT at all.
	var toSync []store.Secret
	for _, sec := range candidates {
		targets, err := a.st.TargetsForSecret(sec.ID)
		if err != nil {
			return err
		}
		if len(targets) > 0 {
			toSync = append(toSync, sec)
		}
	}
	if len(toSync) == 0 {
		fmt.Println("sync complete: 0 pushed, 0 failed")
		return nil
	}

	// Resolved once there is provably something to push, not before: the
	// fallback decrypts the vault's root credential, and doing that for a run
	// with no destinations would write a ledger entry for an authentication that
	// never happened.
	tok, err := ops.ResolveGHToken(a.st, a.key, a.cfg.GitHubToken, cliActor(), store.RoleHuman)
	if err != nil {
		return err
	}
	if tok.Source == ops.TokenFromVault {
		// The vault just decrypted its own root credential. That is the
		// arrangement the README documents, not an incident, but it is not
		// something to do silently either — and the expiry goes with it, since a
		// sync that works today and 401s in a month gives no other warning.
		note := ""
		if s := expiresIn(tok.ExpiresAt); s != "" {
			note = ", expires " + s
		}
		fmt.Fprintf(os.Stderr, "using %s/%s from the vault (SIGNET_GITHUB_TOKEN unset%s)\n",
			ops.GHTokenProject, ops.GHTokenName, note)
	}
	gh := syncpkg.NewGHClient(tok.Value)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pushed, failed := 0, 0
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
				fmt.Printf("  ✗ %s/%s → %s: %s\n", toSync[i].Project, toSync[i].Name, r.Repo, r.Err)
			}
		}
	}
	fmt.Printf("sync complete: %d pushed, %d failed\n", pushed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
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
		want, err := a.projectValues(p)
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
		cur, err := a.st.CurrentVersion(sec.ID)
		if err != nil {
			return err
		}
		vhash := "-"
		if cur != nil {
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
			tgt = append(tgt, fmt.Sprintf("gh:%s→%s [%s]", cfg.Repo, cfg.SecretName, t.GHState(cur)))
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return api.Serve(ctx, a.cfg.Addr, srv)
}
