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
	if _, err := ops.ImportEnv(st, key, "proj", "", env, "test"); err != nil {
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
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Signet-Actor", "magos")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAddTarget(t *testing.T) {
	srv, st, _, _ := testServer(t)
	sec, _ := st.CreateSecret("proj", "TOKEN", "", true, "")
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

func TestSetExpiry(t *testing.T) {
	srv, st, _, _ := testServer(t)
	sec, _ := st.CreateSecret("proj", "TOKEN", "", true, "")
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
	sec, _ := st.CreateSecret("proj", "EXTERNAL_KEY", "", false, "")
	nonce, ct, _ := vault.Encrypt(key, []byte("issued-elsewhere"))
	if _, err := st.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), "test"); err != nil {
		t.Fatal(err)
	}

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
	sec, _ := st.CreateSecret("proj", "GEN_TOKEN", "", true, "")
	val, _ := vault.RandomToken(32)
	nonce, ct, _ := vault.Encrypt(key, []byte(val))
	v1, err := st.AddVersion(sec.ID, nonce, ct, vault.VersionHash(nonce, ct), "test")
	if err != nil {
		t.Fatal(err)
	}

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
