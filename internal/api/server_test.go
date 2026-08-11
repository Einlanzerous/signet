package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/ops"
	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
	"github.com/Einlanzerous/signet/internal/vault"
)

const testToken = "test-token"

func testServer(t *testing.T) (*Server, *store.Store, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := vault.GenerateKey()
	srv, err := New(st, key, nil, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, key, dir
}

// Store mutators live on store.Mutation, so fixtures are seeded through Mutate
// — the same audited path the handlers take. Each seed leaves one entry in the
// chain, older than anything the test goes on to do, so newest-first reads are
// unaffected.

// The kind is a parameter rather than a constant because these entries go into
// the same chain the tests then read back: a seeded target typed as a secret
// write would be a fixture asserting something false about the ledger.
func fixtureRecord(action string, kind store.EventKind) store.AuditRecord {
	return store.AuditRecord{
		Actor: "test", Action: action,
		EventKind: kind, ActorRole: store.RoleHuman,
	}
}

func seedSecret(t *testing.T, st *store.Store, project, name string, generated bool) *store.Secret {
	t.Helper()
	var sec *store.Secret
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		created, err := m.CreateSecret(project, name, "", generated, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		sec = created
		return fixtureRecord("secret.create", store.KindSecretWrite), nil
	}); err != nil {
		t.Fatal(err)
	}
	return sec
}

// seedVersion writes a value with its provenance declared, because AddVersion
// owns the generated column: a helper that always said Minted would silently
// flip an externally-issued fixture into a rotatable one, which is exactly the
// mistake it once made.
func seedVersion(t *testing.T, st *store.Store, secretID string, key []byte, value string, prov store.Provenance) *store.Version {
	t.Helper()
	nonce, ct, err := vault.Encrypt(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	var v *store.Version
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		added, err := m.AddVersion(secretID, nonce, ct, vault.VersionHash(nonce, ct), "test", prov)
		if err != nil {
			return store.AuditRecord{}, err
		}
		v = added
		return fixtureRecord("secret.set", store.KindSecretWrite), nil
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func seedGHTarget(t *testing.T, st *store.Store, secretID, repo, secretName string) *store.Target {
	t.Helper()
	var tgt *store.Target
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		added, err := m.AddGHTarget(secretID, repo, secretName)
		if err != nil {
			return store.AuditRecord{}, err
		}
		tgt = added
		return fixtureRecord("target.add", store.KindTargetConfig), nil
	}); err != nil {
		t.Fatal(err)
	}
	return tgt
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRequired(t *testing.T) {
	srv, _, _, _ := testServer(t)
	h := srv.Handler()
	if rec := get(t, h, "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz should be open: %d", rec.Code)
	}
	if rec := get(t, h, "/v1/mirror/summary", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token should 401: %d", rec.Code)
	}
	if rec := get(t, h, "/v1/mirror/summary", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token should 401: %d", rec.Code)
	}
	if rec := get(t, h, "/v1/mirror/summary", testToken); rec.Code != http.StatusOK {
		t.Fatalf("good token should 200: %d — %s", rec.Code, rec.Body)
	}
}

// TestMirrorNeverLeaksPlaintext is the boundary test: a secret value must not
// appear anywhere in any mirror response.
func TestMirrorNeverLeaksPlaintext(t *testing.T) {
	srv, st, key, dir := testServer(t)
	const sentinel = "SUPER-SENSITIVE-PLAINTEXT-VALUE-42"
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("MY_SECRET="+sentinel+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ImportEnv(st, key, "proj", "", env, "test", store.RoleHuman); err != nil {
		t.Fatal(err)
	}

	h := srv.Handler()
	for _, path := range []string{
		"/v1/mirror/summary",
		"/v1/mirror/secrets",
		"/v1/mirror/secrets/proj/MY_SECRET",
		"/v1/mirror/audit",
	} {
		rec := get(t, h, path, testToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d — %s", path, rec.Code, rec.Body)
		}
		body, _ := io.ReadAll(rec.Body)
		if strings.Contains(string(body), sentinel) {
			t.Fatalf("%s leaked plaintext: %s", path, body)
		}
	}

	// Detail view carries metadata + file target state.
	rec := get(t, h, "/v1/mirror/secrets/proj/MY_SECRET", testToken)
	var detail struct {
		Secret struct {
			VHash   string `json:"vhash"`
			Targets []struct {
				Kind, State string
			} `json:"targets"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Secret.VHash) != 6 {
		t.Fatalf("detail missing vhash: %+v", detail)
	}
	if len(detail.Secret.Targets) != 1 || detail.Secret.Targets[0].State != "in sync" {
		t.Fatalf("file target state wrong: %+v", detail.Secret.Targets)
	}
}

func postCmd(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postCmdWithHeaders(t, h, path, body, map[string]string{"X-Signet-Actor": "magos"})
}

// postCmdWithHeaders issues an authenticated command with caller-set headers.
func postCmdWithHeaders(t *testing.T, h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAddTarget(t *testing.T) {
	srv, st, _, _ := testServer(t)
	sec := seedSecret(t, st, "proj", "TOKEN", true)
	h := srv.Handler()

	// Happy path: default destination name = local name.
	rec := postCmd(t, h, "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"acme/widgets"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add-target: %d — %s", rec.Code, rec.Body)
	}
	targets, _ := st.TargetsForSecret(sec.ID)
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	cfg, _ := targets[0].GHConfig()
	if cfg.Repo != "acme/widgets" || cfg.SecretName != "TOKEN" {
		t.Fatalf("target config wrong: %+v", cfg)
	}
	entries, _ := st.ListAudit(10, sec.ID)
	if len(entries) == 0 || entries[0].Actor != "api:magos" || entries[0].Action != "target.add" {
		t.Fatalf("add-target audit wrong: %+v", entries)
	}

	// Duplicate (same repo + secret name) conflicts.
	if rec := postCmd(t, h, "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"acme/widgets"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate should 409, got %d — %s", rec.Code, rec.Body)
	}

	// Bad repo slug.
	if rec := postCmd(t, h, "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"not-a-slug"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad repo should 400, got %d — %s", rec.Code, rec.Body)
	}

	// Reserved GITHUB_ secret name.
	if rec := postCmd(t, h, "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"acme/widgets","secret_name":"GITHUB_TOKEN"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("reserved name should 400, got %d — %s", rec.Code, rec.Body)
	}

	// Unknown secret.
	if rec := postCmd(t, h, "/v1/commands/add-target", `{"project":"proj","name":"NOPE","repo":"acme/widgets"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown secret should 404, got %d — %s", rec.Code, rec.Body)
	}
}

// A destination the root PAT was never granted is still attached — the grant
// is added by a person, afterwards — but the answer has to say so, or the
// mistake waits until the next sync to surface as a 403 on another secret.
func TestAddTargetWarnsWhenThePATCannotReachTheRepo(t *testing.T) {
	srv, st, _, _ := testServer(t)
	seedSecret(t, st, "proj", "TOKEN", true)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
	}))
	defer gh.Close()
	srv.gh = syncpkg.NewGHClient("tok")
	srv.gh.BaseURL = gh.URL

	rec := postCmd(t, srv.Handler(), "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"acme/widgets"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add-target: %d — %s", rec.Code, rec.Body)
	}
	var body struct {
		Added     bool   `json:"added"`
		Warning   string `json:"warning"`
		Preflight string `json:"preflight"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Added {
		t.Fatal("a repo the PAT cannot reach should still be attached")
	}
	if !strings.Contains(body.Warning, "repository list") {
		t.Fatalf("warning does not name the fix: %q", body.Warning)
	}
	if body.Preflight != string(syncpkg.AccessDenied) {
		t.Fatalf("preflight state = %q, want %q", body.Preflight, syncpkg.AccessDenied)
	}
}

// serve reads SIGNET_PAT as readily as SIGNET_GITHUB_TOKEN, so the message it
// gives when neither is configured has to name both — the daemon is the
// component actually fed from an env file, and its operator is the likeliest
// person to have set the one the old message never mentioned.
func TestSyncDisabledNamesEveryEnvVar(t *testing.T) {
	srv, st, _, _ := testServer(t) // built with gh == nil
	seedSecret(t, st, "proj", "TOKEN", true)

	rec := postCmd(t, srv.Handler(), "/v1/commands/sync", `{"project":"proj","name":"TOKEN"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with no GitHub client, got %d — %s", rec.Code, rec.Body)
	}
	for _, name := range []string{"SIGNET_GITHUB_TOKEN", "SIGNET_PAT"} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Fatalf("sync-disabled message omits %s: %s", name, rec.Body)
		}
	}
}

// A probe that never completed must not read as one that passed. Without the
// state on the response the mirror cannot tell "the PAT can reach this repo"
// from "GitHub did not answer in time", and would show the target as verified
// on the strength of a request that failed.
func TestAddTargetReportsAnInconclusivePreflight(t *testing.T) {
	srv, st, _, _ := testServer(t)
	seedSecret(t, st, "proj", "TOKEN", true)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer gh.Close()
	srv.gh = syncpkg.NewGHClient("tok")
	srv.gh.BaseURL = gh.URL

	rec := postCmd(t, srv.Handler(), "/v1/commands/add-target", `{"project":"proj","name":"TOKEN","repo":"acme/widgets"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add-target: %d — %s", rec.Code, rec.Body)
	}
	var body struct {
		Added     bool   `json:"added"`
		Warning   string `json:"warning"`
		Preflight string `json:"preflight"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Added {
		t.Fatal("an inconclusive probe must not fail the add")
	}
	if body.Preflight != string(syncpkg.AccessUnknown) {
		t.Fatalf("preflight state = %q, want %q", body.Preflight, syncpkg.AccessUnknown)
	}
	// Unattributable, so there is no hint — but the failure still has to surface.
	if body.Warning == "" {
		t.Fatal("an inconclusive probe was dropped entirely")
	}
}

func TestSetExpiry(t *testing.T) {
	srv, st, _, _ := testServer(t)
	sec := seedSecret(t, st, "proj", "TOKEN", true)
	h := srv.Handler()

	// Set an expiry.
	rec := postCmd(t, h, "/v1/commands/set-expiry", `{"project":"proj","name":"TOKEN","expires_at":"2027-01-15"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set-expiry: %d — %s", rec.Code, rec.Body)
	}
	got, _ := st.GetSecretByID(sec.ID)
	if got.ExpiresAt != "2027-01-15T00:00:00Z" {
		t.Fatalf("expiry not stored: %q", got.ExpiresAt)
	}

	// Clear it.
	if rec := postCmd(t, h, "/v1/commands/set-expiry", `{"project":"proj","name":"TOKEN","expires_at":""}`); rec.Code != http.StatusOK {
		t.Fatalf("clear expiry: %d — %s", rec.Code, rec.Body)
	}
	got, _ = st.GetSecretByID(sec.ID)
	if got.ExpiresAt != "" {
		t.Fatalf("expiry not cleared: %q", got.ExpiresAt)
	}

	// Malformed date.
	if rec := postCmd(t, h, "/v1/commands/set-expiry", `{"project":"proj","name":"TOKEN","expires_at":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad date should 400, got %d — %s", rec.Code, rec.Body)
	}

	// Unknown secret.
	if rec := postCmd(t, h, "/v1/commands/set-expiry", `{"project":"proj","name":"NOPE","expires_at":"2027-01-15"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown secret should 404, got %d — %s", rec.Code, rec.Body)
	}
}

func TestRotateExternallyIssuedConflicts(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "proj", "EXTERNAL_KEY", false)
	seedVersion(t, st, sec.ID, key, "issued-elsewhere", store.Issued)

	req := httptest.NewRequest(http.MethodPost, "/v1/commands/rotate",
		strings.NewReader(`{"project":"proj","name":"EXTERNAL_KEY"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("externally issued rotate should 409, got %d — %s", rec.Code, rec.Body)
	}
}

func TestRotateGenerated(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "proj", "GEN_TOKEN", true)
	val, _ := vault.RandomToken(32)
	v1 := seedVersion(t, st, sec.ID, key, val, store.Minted)

	req := httptest.NewRequest(http.MethodPost, "/v1/commands/rotate",
		strings.NewReader(`{"project":"proj","name":"GEN_TOKEN"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Signet-Actor", "magos")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d — %s", rec.Code, rec.Body)
	}
	var resp struct {
		Rotated   bool   `json:"rotated"`
		VersionNo int    `json:"version_no"`
		VHash     string `json:"vhash"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Rotated || resp.VersionNo != v1.VersionNo+1 || resp.VHash == v1.VHash {
		t.Fatalf("rotate response wrong: %+v", resp)
	}
	// Audit records the API actor.
	entries, _ := st.ListAudit(10, sec.ID)
	if len(entries) == 0 || entries[0].Actor != "api:magos" {
		t.Fatalf("rotate audit actor wrong: %+v", entries)
	}
}

// TestActorRoleHeader covers role negotiation at the API boundary: a declared
// role is recorded verbatim, an absent one means a person acting through the
// admin UI, and an unrecognized one is rejected rather than guessed at — a
// mislabeled entry in a tamper-evident ledger is worse than no entry.
func TestActorRoleHeader(t *testing.T) {
	srv, st, _, dir := testServer(t)
	h := srv.Handler()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("MY_SECRET=v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ImportEnv(st, srv.key, "proj", "", env, "test", store.RoleHuman); err != nil {
		t.Fatal(err)
	}
	const body = `{"project":"proj","name":"MY_SECRET","expires_at":"2027-01-01"}`

	// Internal roles cannot be claimed from outside: those entries would be
	// hash-covered and indistinguishable from ones signet wrote itself.
	for _, forged := range []string{"daemon", "healer"} {
		before, err := st.CountAudit()
		if err != nil {
			t.Fatal(err)
		}
		rec := postCmdWithHeaders(t, h, "/v1/commands/set-expiry", body,
			map[string]string{"X-Signet-Actor-Role": forged})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("role %q must not be declarable: %d — %s", forged, rec.Code, rec.Body)
		}
		if after, err := st.CountAudit(); err != nil || after != before {
			t.Fatalf("forged %q must not append: before=%d after=%d err=%v", forged, before, after, err)
		}
	}

	// An unknown role is a 400, and nothing is appended.
	before, err := st.CountAudit()
	if err != nil {
		t.Fatal(err)
	}
	rec := postCmdWithHeaders(t, h, "/v1/commands/set-expiry", body, map[string]string{"X-Signet-Actor-Role": "wizard"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown role should 400: %d — %s", rec.Code, rec.Body)
	}
	if after, err := st.CountAudit(); err != nil || after != before {
		t.Fatalf("rejected request must not append: before=%d after=%d err=%v", before, after, err)
	}

	// A declared role is recorded as given.
	rec = postCmdWithHeaders(t, h, "/v1/commands/set-expiry", body,
		map[string]string{"X-Signet-Actor": "switchyard", "X-Signet-Actor-Role": "rule_engine"})
	if rec.Code != http.StatusOK {
		t.Fatalf("declared role should 200: %d — %s", rec.Code, rec.Body)
	}
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].ActorRole != store.RoleRuleEngine {
		t.Fatalf("declared role not recorded: %+v", entries[0])
	}
	if entries[0].EventKind != store.KindPolicyChange {
		t.Fatalf("event kind wrong: %+v", entries[0])
	}
	if entries[0].Actor != "api:switchyard" {
		t.Fatalf("free-text actor should survive alongside the role: %q", entries[0].Actor)
	}

	// No header: a person acting through the admin UI.
	if rec := postCmdWithHeaders(t, h, "/v1/commands/set-expiry", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("absent role should 200: %d — %s", rec.Code, rec.Body)
	}
	entries, err = st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].ActorRole != store.RoleHuman {
		t.Fatalf("absent role should default to human: %+v", entries[0])
	}

	// The chain stays intact across all of it.
	if ok, badSeq, _, err := st.VerifyAudit(); err != nil || !ok {
		t.Fatalf("chain broken: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// TestBadRoleFailsUniformly: role resolution runs before a handler's own
// validation, so a caller gets the same answer for a bad role whichever command
// it hit — not a 404 here and a 400 there depending on check ordering.
func TestBadRoleFailsUniformly(t *testing.T) {
	srv, _, _, _ := testServer(t)
	h := srv.Handler()
	// Every body below is *also* invalid (no such secret), so a handler that
	// validated first would answer 404 instead.
	for _, c := range []struct{ path, body string }{
		{"/v1/commands/sync", `{"project":"nope","name":"NOPE"}`},
		{"/v1/commands/rotate", `{"project":"nope","name":"NOPE"}`},
		{"/v1/commands/add-target", `{"project":"nope","name":"NOPE","repo":"o/r"}`},
		{"/v1/commands/set-expiry", `{"project":"nope","name":"NOPE"}`},
	} {
		rec := postCmdWithHeaders(t, h, c.path, c.body, map[string]string{"X-Signet-Actor-Role": "healer"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400 for an undeclarable role, got %d — %s", c.path, rec.Code, rec.Body)
		}
	}
}

// TestSetExpiryNoOpOutcome: re-sending the expiry a secret already has is not
// an update, and the ledger should not claim it was.
func TestSetExpiryNoOpOutcome(t *testing.T) {
	srv, st, _, _ := testServer(t)
	h := srv.Handler()
	seedSecret(t, st, "proj", "TOKEN", true)
	const body = `{"project":"proj","name":"TOKEN","expires_at":"2027-01-01"}`

	if rec := postCmd(t, h, "/v1/commands/set-expiry", body); rec.Code != http.StatusOK {
		t.Fatalf("first set: %d — %s", rec.Code, rec.Body)
	}
	entries, _ := st.ListAudit(1, "")
	if entries[0].Status.Outcome != store.OutcomeUpdated {
		t.Fatalf("first set should be an update: %+v", entries[0].Status)
	}

	// Same value again: nothing changed.
	if rec := postCmd(t, h, "/v1/commands/set-expiry", body); rec.Code != http.StatusOK {
		t.Fatalf("repeat set: %d — %s", rec.Code, rec.Body)
	}
	entries, _ = st.ListAudit(1, "")
	if entries[0].Status.Outcome != store.OutcomeUnchanged {
		t.Fatalf("repeat set should be unchanged, got %q", entries[0].Status.Outcome)
	}
}

// TestSummaryReportsHealerWindow checks the healer-actions aggregate the tile
// reads. It is empty until the healer phase lands, and must not be inferred
// from unrelated entries.
func TestSummaryReportsHealerWindow(t *testing.T) {
	srv, st, _, _ := testServer(t)
	h := srv.Handler()

	var summary struct {
		HealerActions map[string]int `json:"healer_actions_7d"`
	}
	rec := get(t, h, "/v1/mirror/summary", testToken)
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.HealerActions) != 0 {
		t.Fatalf("no healer yet, tile must report nothing: %+v", summary.HealerActions)
	}

	if _, err := st.AppendHealerAction("healer", store.ActionHealerRestart, "restarted postgres", store.OutcomeAutoResolved); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendHealerAction("healer", store.ActionHealerRollback, "rolled back caddy", store.OutcomeReverted); err != nil {
		t.Fatal(err)
	}
	rec = get(t, h, "/v1/mirror/summary", testToken)
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.HealerActions["auto_resolved"] != 1 || summary.HealerActions["reverted"] != 1 {
		t.Fatalf("healer window wrong: %+v", summary.HealerActions)
	}

	// An entry with no status must not produce a blank JSON member name.
	if _, err := st.AppendAudit(store.AuditRecord{
		Actor: "healer", Action: store.ActionHealerRecreate, Details: "no status recorded",
		EventKind: store.KindHealerAction, ActorRole: store.RoleHealer,
	}); err != nil {
		t.Fatal(err)
	}
	rec = get(t, h, "/v1/mirror/summary", testToken)
	if strings.Contains(rec.Body.String(), `"":`) {
		t.Fatalf("summary must not emit a blank key: %s", rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.HealerActions[string(store.OutcomeUnspecified)] != 1 {
		t.Fatalf("statusless entry should land in the named bucket: %+v", summary.HealerActions)
	}
}

// TestRemoveTargetCommand covers the mirror's detach command: it removes the
// record, audits it with the removed outcome, says the remote secret was left
// alone, and 404s rather than silently succeeding on something that is not there.
func TestRemoveTargetCommand(t *testing.T) {
	srv, st, _, _ := testServer(t)
	sec := seedSecret(t, st, "proj", "TOKEN", true)
	seedGHTarget(t, st, sec.ID, "owner/repo", "TOKEN")
	h := srv.Handler()
	const body = `{"project":"proj","name":"TOKEN","repo":"owner/repo"}`

	rec := postCmd(t, h, "/v1/commands/remove-target", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove should 200: %d — %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "left in place") {
		t.Fatalf("response must state the remote secret was not deleted: %s", rec.Body)
	}
	targets, err := st.TargetsForSecret(sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("target not detached: %+v", targets)
	}
	entries, err := st.ListAudit(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Action != "target.rm" || entries[0].EventKind != store.KindTargetConfig {
		t.Fatalf("audit entry wrong: %+v", entries[0])
	}
	if entries[0].Status == nil || entries[0].Status.Outcome != store.OutcomeRemoved {
		t.Fatalf("outcome should be removed: %+v", entries[0].Status)
	}

	// Removing it again is a 404, and appends nothing.
	before, _ := st.CountAudit()
	if rec := postCmd(t, h, "/v1/commands/remove-target", body); rec.Code != http.StatusNotFound {
		t.Fatalf("second remove should 404: %d — %s", rec.Code, rec.Body)
	}
	if after, _ := st.CountAudit(); after != before {
		t.Fatalf("failed remove must not append: before=%d after=%d", before, after)
	}

	// Unknown secret is a 404 too, not a 500.
	if rec := postCmd(t, h, "/v1/commands/remove-target", `{"project":"nope","name":"NOPE","repo":"o/r"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown secret should 404: %d — %s", rec.Code, rec.Body)
	}
	if ok, badSeq, _, err := st.VerifyAudit(); err != nil || !ok {
		t.Fatalf("chain broken: ok=%v badSeq=%d err=%v", ok, badSeq, err)
	}
}

// A derived secret whose derivation cannot resolve must never be reported
// healthy. GHState answers "in sync" when given neither a version nor a digest,
// so the mirror has to keep an unresolvable secret away from it entirely — this
// is the bug the first fix for the mirror re-created in its own error branch.
func TestMirrorNeverReportsAnUnresolvableSecretInSync(t *testing.T) {
	srv, st, _, _ := testServer(t)

	var secID string
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		sec, err := m.CreateSecret("drydock", "DSN", "", false, "")
		if err != nil {
			return store.AuditRecord{}, err
		}
		secID = sec.ID
		if err := m.SetDerivation(sec.ID, "postgres://u:{{construct-server/MISSING}}@h/db"); err != nil {
			return store.AuditRecord{}, err
		}
		if _, err := m.AddGHTarget(sec.ID, "owner/repo", "DSN"); err != nil {
			return store.AuditRecord{}, err
		}
		return store.AuditRecord{Actor: "test", Action: "seed", SecretID: sec.ID,
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman}, nil
	}); err != nil {
		t.Fatal(err)
	}
	// A prior successful push, so the target is past the "never" state and the
	// switch actually reaches the comparison being tested.
	tgts, err := st.TargetsForSecret(secID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateTargetPush(tgts[0].ID, "in sync", "",
		&store.PushProvenance{Digest: "aaaaaaaaaaaa"}, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	views, err := srv.buildViews()
	if err != nil {
		t.Fatalf("one unresolvable secret blanked the whole mirror: %v", err)
	}
	var sv *SecretView
	for i := range views {
		for j := range views[i].Secrets {
			if views[i].Secrets[j].Name == "DSN" {
				sv = &views[i].Secrets[j]
			}
		}
	}
	if sv == nil {
		t.Fatal("mirror dropped the unresolvable secret entirely")
	}
	if sv.Unresolved == "" {
		t.Error("nothing on the view distinguishes an unresolvable secret from a healthy derived one")
	}
	for _, tv := range sv.Targets {
		if tv.State == "in sync" {
			t.Errorf("target reported %q for a secret that cannot be computed", tv.State)
		}
	}
}
