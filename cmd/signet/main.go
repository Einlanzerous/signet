// Command signet is the construct-server credential vault and outbound-sync
// control plane (IDEA-13, first slice): a host-resident single static binary
// that is both a CLI and a thin HTTP API.
//
//	signet init                                    # create master key + database
//	signet import --project lyceum ~/projects/lyceum/.env
//	signet set --project csrv --name API_TOKEN --generate
//	signet reveal --project csrv --name API_TOKEN  # audited
//	signet render --project lyceum [--check]       # write / drift-check file targets
//	signet target add --secret csrv/RELEASE_BOT_PRIVATE_KEY --gh-repo Einlanzerous/purser
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
	if _, err := st.AppendAudit(cliActor(), "vault.init", "", "", "master key + database created"); err != nil {
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

	res, err := ops.ImportEnv(a.st, a.key, *project, *scope, path, cliActor())
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
	action := "secret.update"
	if sec == nil {
		if sec, err = a.st.CreateSecret(*project, *name, *scope, *generate, expiresAt); err != nil {
			return err
		}
		action = "secret.create"
	}
	nonce, ct, err := vault.Encrypt(a.key, []byte(value))
	if err != nil {
		return err
	}
	v, err := a.st.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), cliActor())
	if err != nil {
		return err
	}
	if _, err := a.st.AppendAudit(cliActor(), action, sec.ID, "",
		fmt.Sprintf("%s/%s · version %d #%s", *project, *name, v.VersionNo, v.VHash)); err != nil {
		return err
	}
	fmt.Printf("%s/%s → version %d #%s\n", *project, *name, v.VersionNo, v.VHash)
	return nil
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
	if _, err := a.st.AppendAudit(cliActor(), "secret.reveal", sec.ID, "",
		fmt.Sprintf("revealed %s/%s version %d #%s to stdout", *project, *name, cur.VersionNo, cur.VHash)); err != nil {
		return err
	}
	fmt.Println(string(plain))
	return nil
}

// ---- render -----------------------------------------------------------------

func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	project := fs.String("project", "", "project (required)")
	check := fs.Bool("check", false, "report drift without writing")
	fs.Parse(args)
	if *project == "" {
		return fmt.Errorf("usage: signet render --project <p> [--check]")
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
			drift := syncpkg.CheckFile(cfg.Path, want, cfg.Keys)
			printDrift(drift)
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
		if err := atomicWrite(cfg.Path, envfile.Render(pairs), cfg.Mode); err != nil {
			return err
		}
		_ = a.st.UpdateTargetPush(t.ID, "in sync", "", "", time.Now().UTC().Format(time.RFC3339))
		if _, err := a.st.AppendAudit(cliActor(), "render", "", t.ID,
			fmt.Sprintf("rendered %d keys → %s (mode %s)", len(pairs), cfg.Path, cfg.Mode)); err != nil {
			return err
		}
		fmt.Printf("rendered %s (%d keys)\n", cfg.Path, len(pairs))
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

func printDrift(d syncpkg.FileDrift) {
	if d.MissingFile {
		fmt.Printf("%s: MISSING FILE\n", d.Path)
		return
	}
	if d.Clean() {
		fmt.Printf("%s: in sync (%d keys)\n", d.Path, len(d.Keys))
	} else {
		fmt.Printf("%s: DRIFT\n", d.Path)
		for _, k := range d.Keys {
			if k.State != "ok" {
				fmt.Printf("  %-40s %s\n", k.Key, k.State)
			}
		}
	}
	if len(d.Unmanaged) > 0 {
		fmt.Printf("  unmanaged keys in file: %s\n", strings.Join(d.Unmanaged, ", "))
	}
}

func atomicWrite(path, content, mode string) error {
	perm := os.FileMode(0o600)
	if mode != "" {
		var parsed uint32
		if _, err := fmt.Sscanf(mode, "%o", &parsed); err == nil {
			perm = os.FileMode(parsed)
		}
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
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ---- target -----------------------------------------------------------------

func runTarget(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return fmt.Errorf("usage: signet target add --secret <p>/<NAME> --gh-repo owner/name [--gh-secret NAME]")
	}
	fs := flag.NewFlagSet("target add", flag.ExitOnError)
	ref := fs.String("secret", "", "secret ref project/NAME (required)")
	ghRepo := fs.String("gh-repo", "", "GitHub repo owner/name (required)")
	ghSecret := fs.String("gh-secret", "", "destination Actions secret name (default: local name)")
	fs.Parse(args[1:])
	if *ref == "" || *ghRepo == "" || !strings.Contains(*ghRepo, "/") {
		return fmt.Errorf("usage: signet target add --secret <p>/<NAME> --gh-repo owner/name [--gh-secret NAME]")
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
	t, err := a.st.AddGHTarget(sec.ID, *ghRepo, dest)
	if err != nil {
		return err
	}
	if _, err := a.st.AppendAudit(cliActor(), "target.add", sec.ID, t.ID,
		fmt.Sprintf("%s/%s → %s · Actions secret %s", project, name, *ghRepo, dest)); err != nil {
		return err
	}
	fmt.Printf("target added: %s/%s → %s (Actions secret %s)\n", project, name, *ghRepo, dest)
	fmt.Println("run `signet sync` to push")
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
	if a.cfg.GitHubToken == "" {
		return fmt.Errorf("SIGNET_GITHUB_TOKEN is not set — cannot push to GitHub Actions")
	}
	gh := syncpkg.NewGHClient(a.cfg.GitHubToken)

	var toSync []store.Secret
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
		toSync = []store.Secret{*sec}
	} else {
		all, err := a.st.ListSecrets()
		if err != nil {
			return err
		}
		for _, sec := range all {
			targets, err := a.st.TargetsForSecret(sec.ID)
			if err != nil {
				return err
			}
			if len(targets) > 0 {
				toSync = append(toSync, sec)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pushed, failed := 0, 0
	for i := range toSync {
		results, err := syncpkg.PushSecret(ctx, a.st, a.key, gh, &toSync[i], cliActor())
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
		if sec.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, sec.ExpiresAt); err == nil {
				days := int(time.Until(t).Hours() / 24)
				expires = fmt.Sprintf("%s (%dd)", t.Format("2006-01-02"), days)
			}
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
			state := "never"
			switch {
			case t.LastError != "":
				state = "error"
			case t.LastPushedAt == "":
				state = "never"
			case cur != nil && t.LastPushedVersionID != cur.ID:
				state = "drift"
			default:
				state = "in sync"
			}
			tgt = append(tgt, fmt.Sprintf("gh:%s→%s [%s]", cfg.Repo, cfg.SecretName, state))
		}
		for _, fi := range fileByProject[sec.Project] {
			if !contains(fi.cfg.Keys, sec.Name) {
				continue
			}
			state := "in sync"
			if fi.drift.MissingFile {
				state = "missing"
			} else {
				for _, ks := range fi.drift.Keys {
					if ks.Key == sec.Name && ks.State != "ok" {
						state = ks.State
					}
				}
			}
			tgt = append(tgt, fmt.Sprintf("file:%s [%s]", fi.cfg.Path, state))
		}
		if len(tgt) == 0 {
			tgt = []string{"-"}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", sec.Project, sec.Name, vhash, sec.Status, expires, strings.Join(tgt, ", "))
	}
	return w.Flush()
}

func contains(xs []string, s string) bool {
	i := sort.SearchStrings(xs, s)
	return i < len(xs) && xs[i] == s
}

// ---- audit ------------------------------------------------------------------

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
	fmt.Fprintln(w, "SEQ\tTS\tACTOR\tACTION\tDETAILS\tHASH")
	for _, e := range entries {
		details := e.Details
		if len(details) > 80 {
			details = details[:77] + "…"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s…\n", e.Seq, e.TS, e.Actor, e.Action, details, e.Hash[:6])
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
