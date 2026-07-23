// Package api is signet's thin HTTP surface: a read-only "blind mirror" for
// the Switchyard admin UI plus a small command set (sync, rotate) that is
// issued to the daemon — never performed by the caller.
//
// The API NEVER returns plaintext secret values. The daemon holds the vault
// key internally (it needs it to seal pushes and check file drift), but only
// metadata, version hashes, sync state, and audit entries cross this boundary.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
	"github.com/Einlanzerous/signet/internal/vault"
	"github.com/Einlanzerous/signet/internal/version"
)

// Server wires the store, vault key, and GitHub client behind HTTP handlers.
type Server struct {
	st       *store.Store
	key      []byte
	gh       *syncpkg.GHClient
	apiToken string
}

// New builds a Server. gh may be nil when no GitHub token is configured.
func New(st *store.Store, key []byte, gh *syncpkg.GHClient, apiToken string) (*Server, error) {
	if apiToken == "" {
		return nil, errors.New("api: SIGNET_API_TOKEN must be set to serve")
	}
	return &Server{st: st, key: key, gh: gh, apiToken: apiToken}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version.Version})
	})
	mux.Handle("GET /v1/mirror/summary", s.auth(s.handleSummary))
	mux.Handle("GET /v1/mirror/secrets", s.auth(s.handleSecrets))
	mux.Handle("GET /v1/mirror/secrets/{project}/{name}", s.auth(s.handleSecretDetail))
	mux.Handle("GET /v1/mirror/audit", s.auth(s.handleAudit))
	mux.Handle("POST /v1/commands/sync", s.auth(s.handleCommandSync))
	mux.Handle("POST /v1/commands/rotate", s.auth(s.handleCommandRotate))
	mux.Handle("POST /v1/commands/add-target", s.auth(s.handleCommandAddTarget))
	mux.Handle("POST /v1/commands/set-expiry", s.auth(s.handleCommandSetExpiry))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if len(got) <= len(prefix) ||
			subtle.ConstantTimeCompare([]byte(got[:len(prefix)]), []byte(prefix)) != 1 ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(s.apiToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		next(w, r)
	})
}

func (s *Server) actor(r *http.Request) string {
	if who := r.Header.Get("X-Signet-Actor"); who != "" {
		return "api:" + who
	}
	return "api"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, map[string]string{"error": fmt.Sprintf(format, args...)})
}

// ---- mirror views -----------------------------------------------------------

// TargetView is a target's blind mirror representation.
type TargetView struct {
	Kind         string             `json:"kind"`
	Repo         string             `json:"repo,omitempty"`
	SecretName   string             `json:"secret_name,omitempty"`
	Path         string             `json:"path,omitempty"`
	State        string             `json:"state"`
	LastPushedAt string             `json:"last_pushed_at,omitempty"`
	LastError    string             `json:"last_error,omitempty"`
	Keys         []syncpkg.KeyState `json:"keys,omitempty"`
}

// SecretView is a secret's blind mirror representation. No values, ever.
type SecretView struct {
	Name      string       `json:"name"`
	Scope     string       `json:"scope,omitempty"`
	Status    string       `json:"status"`
	Generated bool         `json:"generated"`
	VHash     string       `json:"vhash,omitempty"`
	VersionNo int          `json:"version_no"`
	ExpiresAt string       `json:"expires_at,omitempty"`
	UpdatedAt string       `json:"updated_at"`
	Targets   []TargetView `json:"targets,omitempty"`
}

// ProjectView groups a project's secrets.
type ProjectView struct {
	Project string       `json:"project"`
	Secrets []SecretView `json:"secrets"`
}

// buildViews assembles the full blind mirror, computing sync state locally
// (no network calls — remote drift is refreshed by sync operations).
func (s *Server) buildViews() ([]ProjectView, error) {
	secrets, err := s.st.ListSecrets()
	if err != nil {
		return nil, err
	}
	byProject := map[string][]store.Secret{}
	var projects []string
	for _, sec := range secrets {
		if _, seen := byProject[sec.Project]; !seen {
			projects = append(projects, sec.Project)
		}
		byProject[sec.Project] = append(byProject[sec.Project], sec)
	}
	sort.Strings(projects)

	var out []ProjectView
	for _, project := range projects {
		pv := ProjectView{Project: project}
		secs := byProject[project]

		// Decrypt current values once per project for file-drift checks.
		want := map[string]string{}
		current := map[string]*store.Version{}
		for i := range secs {
			cur, err := s.st.CurrentVersion(secs[i].ID)
			if err != nil {
				return nil, err
			}
			current[secs[i].Name] = cur
			if cur != nil {
				plain, err := vault.Decrypt(s.key, cur.Nonce, cur.Ciphertext)
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", project, secs[i].Name, err)
				}
				want[secs[i].Name] = string(plain)
			}
		}

		fileTargets, err := s.st.FileTargetsForProject(project)
		if err != nil {
			return nil, err
		}
		type fileCheck struct {
			target store.Target
			cfg    store.FileConfig
			drift  syncpkg.FileDrift
		}
		var checks []fileCheck
		for _, ft := range fileTargets {
			cfg, err := ft.FileConfig()
			if err != nil {
				return nil, err
			}
			checks = append(checks, fileCheck{ft, cfg, syncpkg.CheckFile(cfg.Path, want, cfg.Keys)})
		}

		for i := range secs {
			sec := secs[i]
			sv := SecretView{
				Name: sec.Name, Scope: sec.Scope, Status: sec.Status,
				Generated: sec.Generated, ExpiresAt: sec.ExpiresAt, UpdatedAt: sec.UpdatedAt,
			}
			cur := current[sec.Name]
			if cur != nil {
				sv.VHash = cur.VHash
				sv.VersionNo = cur.VersionNo
			}
			ghTargets, err := s.st.TargetsForSecret(sec.ID)
			if err != nil {
				return nil, err
			}
			for _, t := range ghTargets {
				cfg, err := t.GHConfig()
				if err != nil {
					return nil, err
				}
				sv.Targets = append(sv.Targets, TargetView{
					Kind: t.Kind, Repo: cfg.Repo, SecretName: cfg.SecretName,
					State:        ghState(t, cur),
					LastPushedAt: t.LastPushedAt, LastError: t.LastError,
				})
			}
			for _, fc := range checks {
				if state, managed := keyState(fc.drift, sec.Name, fc.cfg.Keys); managed {
					sv.Targets = append(sv.Targets, TargetView{Kind: "file", Path: fc.cfg.Path, State: state})
				}
			}
			pv.Secrets = append(pv.Secrets, sv)
		}
		out = append(out, pv)
	}
	return out, nil
}

// ghState computes a gh-actions target's local sync state.
func ghState(t store.Target, cur *store.Version) string {
	switch {
	case t.LastError != "":
		return "error"
	case t.LastPushedAt == "":
		return "never"
	case cur != nil && t.LastPushedVersionID != cur.ID:
		return "drift" // vault moved on; destination holds an old version
	default:
		return "in sync"
	}
}

// keyState extracts one key's drift state from a file target's report.
func keyState(d syncpkg.FileDrift, key string, managed []string) (string, bool) {
	for _, m := range managed {
		if m != key {
			continue
		}
		if d.MissingFile {
			return "missing", true
		}
		for _, ks := range d.Keys {
			if ks.Key == key {
				if ks.State == "ok" {
					return "in sync", true
				}
				return ks.State, true
			}
		}
		return "missing", true
	}
	return "", false
}

// ---- handlers ---------------------------------------------------------------

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	views, err := s.buildViews()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build mirror: %v", err)
		return
	}
	secretCount := 0
	states := map[string]int{}
	for _, pv := range views {
		secretCount += len(pv.Secrets)
		for _, sv := range pv.Secrets {
			for _, t := range sv.Targets {
				states[t.State]++
			}
		}
	}
	auditCount, err := s.st.CountAudit()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "count audit: %v", err)
		return
	}
	verified, _, _, err := s.st.VerifyAudit()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "verify audit: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secrets":        secretCount,
		"projects":       len(views),
		"target_states":  states,
		"audit_entries":  auditCount,
		"chain_verified": verified,
	})
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	views, err := s.buildViews()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build mirror: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": views})
}

func (s *Server) handleSecretDetail(w http.ResponseWriter, r *http.Request) {
	project, name := r.PathValue("project"), r.PathValue("name")
	sec, err := s.st.GetSecret(project, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if sec == nil {
		writeErr(w, http.StatusNotFound, "no secret %s/%s", project, name)
		return
	}
	views, err := s.buildViews()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build mirror: %v", err)
		return
	}
	var found *SecretView
	for _, pv := range views {
		if pv.Project != project {
			continue
		}
		for i := range pv.Secrets {
			if pv.Secrets[i].Name == name {
				found = &pv.Secrets[i]
			}
		}
	}
	audit, err := s.st.ListAudit(50, sec.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": project, "secret": found, "audit": audit})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		fmt.Sscanf(q, "%d", &limit)
	}
	entries, err := s.st.ListAudit(limit, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	verified, badSeq, total, err := s.st.VerifyAudit()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries, "chain_verified": verified, "chain_length": total, "first_broken_seq": badSeq,
	})
}

type commandReq struct {
	Project string `json:"project"`
	Name    string `json:"name"`
}

func (s *Server) decodeCommand(w http.ResponseWriter, r *http.Request) (*store.Secret, bool) {
	var req commandReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "body must be {\"project\": ..., \"name\": ...}")
		return nil, false
	}
	sec, err := s.st.GetSecret(req.Project, req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return nil, false
	}
	if sec == nil {
		writeErr(w, http.StatusNotFound, "no secret %s/%s", req.Project, req.Name)
		return nil, false
	}
	return sec, true
}

func (s *Server) handleCommandSync(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.decodeCommand(w, r)
	if !ok {
		return
	}
	if s.gh == nil {
		writeErr(w, http.StatusServiceUnavailable, "gh-actions sync disabled: SIGNET_GITHUB_TOKEN not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	results, err := syncpkg.PushSecret(ctx, s.st, s.key, s.gh, sec, s.actor(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleCommandRotate(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.decodeCommand(w, r)
	if !ok {
		return
	}
	if !sec.Generated {
		writeErr(w, http.StatusConflict,
			"secret %s/%s is externally issued — signet can fan out a new value but cannot mint one; rotate it at the issuer, then `signet set`", sec.Project, sec.Name)
		return
	}
	value, err := vault.RandomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	nonce, ct, err := vault.Encrypt(s.key, []byte(value))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	v, err := s.st.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), s.actor(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if _, err := s.st.AppendAudit(s.actor(r), "rotate", sec.ID, "",
		fmt.Sprintf("rotated %s/%s → version %d #%s — fan-out queued", sec.Project, sec.Name, v.VersionNo, v.VHash)); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	resp := map[string]any{"rotated": true, "version_no": v.VersionNo, "vhash": v.VHash}
	if s.gh != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if results, err := syncpkg.PushSecret(ctx, s.st, s.key, s.gh, sec, s.actor(r)); err == nil {
			resp["fan_out"] = results
		} else {
			resp["fan_out_error"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- add-target / set-expiry ------------------------------------------------

// ghRepoRe matches a GitHub owner/name slug: two dot/dash/underscore/alnum
// segments separated by a single slash.
var ghRepoRe = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// ghSecretRe matches a legal GitHub Actions secret name: alphanumerics and
// underscores, not starting with a digit. GITHUB_-prefixed names are rejected
// separately (GitHub reserves them).
var ghSecretRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validGHSecretName(name string) bool {
	return ghSecretRe.MatchString(name) && !strings.HasPrefix(strings.ToUpper(name), "GITHUB_")
}

type addTargetReq struct {
	Project    string `json:"project"`
	Name       string `json:"name"`
	Repo       string `json:"repo"`
	SecretName string `json:"secret_name"`
}

// handleCommandAddTarget attaches a gh-actions fan-out destination to a secret.
// It validates the repo slug and destination Actions secret name, rejects a
// duplicate (same repo + secret name), and audits the change. It does not push
// — the caller issues a sync afterward.
func (s *Server) handleCommandAddTarget(w http.ResponseWriter, r *http.Request) {
	var req addTargetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" || req.Name == "" || req.Repo == "" {
		writeErr(w, http.StatusBadRequest, `body must be {"project": ..., "name": ..., "repo": "owner/name", "secret_name": ...(optional)}`)
		return
	}
	if !ghRepoRe.MatchString(req.Repo) {
		writeErr(w, http.StatusBadRequest, "repo %q must be of the form owner/name", req.Repo)
		return
	}
	dest := req.SecretName
	if dest == "" {
		dest = req.Name
	}
	if !validGHSecretName(dest) {
		writeErr(w, http.StatusBadRequest, "secret_name %q is not a valid GitHub Actions secret name (alphanumeric/underscore, not starting with a digit or GITHUB_)", dest)
		return
	}
	sec, err := s.st.GetSecret(req.Project, req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if sec == nil {
		writeErr(w, http.StatusNotFound, "no secret %s/%s", req.Project, req.Name)
		return
	}
	existing, err := s.st.TargetsForSecret(sec.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	for _, t := range existing {
		cfg, err := t.GHConfig()
		if err != nil {
			continue
		}
		if cfg.Repo == req.Repo && cfg.SecretName == dest {
			writeErr(w, http.StatusConflict, "target already exists: %s → %s (Actions secret %s)", req.Repo, dest, dest)
			return
		}
	}
	t, err := s.st.AddGHTarget(sec.ID, req.Repo, dest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if _, err := s.st.AppendAudit(s.actor(r), "target.add", sec.ID, t.ID,
		fmt.Sprintf("%s/%s → %s · Actions secret %s", req.Project, req.Name, req.Repo, dest)); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"added":  true,
		"target": TargetView{Kind: t.Kind, Repo: req.Repo, SecretName: dest, State: "never"},
	})
}

type setExpiryReq struct {
	Project   string `json:"project"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"` // YYYY-MM-DD, or "" to clear
}

// handleCommandSetExpiry sets or clears a secret's expiry date. An empty
// expires_at clears it; otherwise the value must be a YYYY-MM-DD date.
func (s *Server) handleCommandSetExpiry(w http.ResponseWriter, r *http.Request) {
	var req setExpiryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, `body must be {"project": ..., "name": ..., "expires_at": "YYYY-MM-DD" (empty to clear)}`)
		return
	}
	expiresAt := ""
	if req.ExpiresAt != "" {
		d, err := time.Parse("2006-01-02", req.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_at must be YYYY-MM-DD: %v", err)
			return
		}
		expiresAt = d.UTC().Format(time.RFC3339)
	}
	sec, err := s.st.GetSecret(req.Project, req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if sec == nil {
		writeErr(w, http.StatusNotFound, "no secret %s/%s", req.Project, req.Name)
		return
	}
	if err := s.st.SetExpiry(sec.ID, expiresAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	detail := req.Project + "/" + req.Name + ": cleared expiry"
	if expiresAt != "" {
		detail = fmt.Sprintf("%s/%s: expiry set to %s", req.Project, req.Name, req.ExpiresAt)
	}
	if _, err := s.st.AppendAudit(s.actor(r), "secret.set-expiry", sec.ID, "", detail); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project": req.Project, "name": req.Name, "expires_at": expiresAt,
	})
}

// Serve runs the API server until ctx is cancelled.
func Serve(ctx context.Context, addr string, s *Server) error {
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("api listening on %s", addr)
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
