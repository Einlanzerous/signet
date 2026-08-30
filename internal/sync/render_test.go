package sync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// An environment secret lives behind a different path from a repository one and
// seals with a different key. Both halves have to move together: sealing with
// the repository key and PUTting to the environment path yields a secret GitHub
// stores happily and no workflow can read.
func TestEnvironmentSecretsUseTheEnvironmentEndpoints(t *testing.T) {
	pub, _, _ := box.GenerateKey(rand.Reader)
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/environments/home-server/secrets/public-key", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "env public-key")
		json.NewEncoder(w).Encode(PublicKey{KeyID: "env-key", Key: base64.StdEncoding.EncodeToString(pub[:])})
	})
	mux.HandleFunc("PUT /repos/o/r/environments/home-server/secrets/PROD_ENV_FILE", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "env put")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /repos/o/r/environments/home-server/secrets/PROD_ENV_FILE", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "env meta")
		json.NewEncoder(w).Encode(SecretMeta{Name: "PROD_ENV_FILE", UpdatedAt: "2026-07-01T12:00:00Z"})
	})
	// The repository paths must never be touched for an environment target.
	// Without this the test would pass on a client that quietly fell back.
	mux.HandleFunc("/repos/o/r/actions/secrets/", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, "REPO SCOPE: "+r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	ctx := context.Background()

	pk, _, err := c.RepoPublicKey(ctx, "o/r", "home-server")
	if err != nil {
		t.Fatal(err)
	}
	if pk.KeyID != "env-key" {
		t.Fatalf("sealed against %q, not the environment key", pk.KeyID)
	}
	if _, err := c.PutSecret(ctx, "o/r", "home-server", "PROD_ENV_FILE", "c2VhbGVk", pk.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSecretMeta(ctx, "o/r", "home-server", "PROD_ENV_FILE"); err != nil {
		t.Fatal(err)
	}
	want := []string{"env public-key", "env put", "env meta"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

// An environment name is free text — a space or a slash in one must not become
// a different path than the one that was asked for.
func TestEnvironmentNameIsEscapedIntoThePath(t *testing.T) {
	if got := secretsBase("o/r", "home server"); got != "/repos/o/r/environments/home%20server/secrets" {
		t.Fatalf("secretsBase = %q", got)
	}
	// The repository slug's own "/" is structural and must survive intact.
	if got := secretsBase("owner/name", ""); got != "/repos/owner/name/actions/secrets" {
		t.Fatalf("secretsBase = %q", got)
	}
}

// The whole point of the kind: a key the vault cannot supply must stop the
// push, not shorten the file. An absent key interpolates to empty at the
// consumer, which is how three production incidents happened.
func TestRenderBlobRefusesWhenAKeyHasNoValue(t *testing.T) {
	cfg := store.GHRenderConfig{Keys: []string{"ALPHA", "BETA", "GAMMA"}}
	_, err := RenderBlob(cfg, "csrv", map[string]string{"BETA": "b"})
	var missing *MissingKeysError
	if !errorAs(err, &missing) {
		t.Fatalf("err = %v, want MissingKeysError", err)
	}
	if strings.Join(missing.Keys, ",") != "ALPHA,GAMMA" {
		t.Fatalf("missing = %v", missing.Keys)
	}
}

// The blob is hashed to decide drift against a destination that can never be
// read back, so the same values must always produce the same bytes.
func TestRenderBlobIsStableAndCarriesTheBlobHeader(t *testing.T) {
	cfg := store.GHRenderConfig{Keys: []string{"BETA", "ALPHA"}}
	want := map[string]string{"ALPHA": "a", "BETA": "b"}
	first, err := RenderBlob(cfg, "csrv", want)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderBlob(store.GHRenderConfig{Keys: []string{"ALPHA", "BETA"}}, "csrv", want)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("key order changed the blob:\n%q\n%q", first, second)
	}
	if !strings.HasPrefix(first, envfile.BlobHeader) {
		t.Fatalf("blob does not open with the blob header: %q", first)
	}
	// The file-target header promises that unmanaged lines are kept. Nothing
	// keeps them here, so it must not appear.
	if strings.Contains(first, envfile.Header) {
		t.Fatal("blob carries the file-target header, which promises something a blob does not do")
	}
	if _, err := envfile.Parse(strings.NewReader(first)); err != nil {
		t.Fatalf("blob does not parse back as an env file: %v", err)
	}
}

func TestDroppedKeysIgnoresOrderAndReportsOnlyLosses(t *testing.T) {
	got := DroppedKeys([]string{"A", "B", "C"}, []string{"C", "A", "D"})
	if strings.Join(got, ",") != "B" {
		t.Fatalf("dropped = %v", got)
	}
	if len(DroppedKeys([]string{"A"}, []string{"A", "B"})) != 0 {
		t.Fatal("a grown key set reported a loss")
	}
}

// renderFixture builds a vault with a project of stored secrets and one
// gh-render target pointed at srv.
func renderFixture(t *testing.T, baseURL string, keys []string, values map[string]string) (*store.Store, []byte, *store.Target) {
	t.Helper()
	return renderFixtureAt(t, filepath.Join(t.TempDir(), "db"), baseURL, keys, values)
}

// renderFixtureAt is renderFixture at a caller-chosen path, for the tests that
// need a second connection to the same database — see refuseWrites.
func renderFixtureAt(t *testing.T, path, baseURL string, keys []string, values map[string]string) (*store.Store, []byte, *store.Target) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range values {
		nonce, ct, err := vault.Encrypt(key, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
			s, err := m.CreateSecret("csrv", name, "", false, "")
			if err != nil {
				return store.AuditRecord{}, err
			}
			if _, err := m.AddVersion(s.ID, nonce, ct, vault.VersionHash(nonce, ct), "test", store.Minted); err != nil {
				return store.AuditRecord{}, err
			}
			return store.AuditRecord{
				Actor: "test", Action: "secret.set", SecretID: s.ID, Details: "fixture",
				EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
				Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
			}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	target, _, err := store.MutateValue(st, func(m *store.Mutation) (*store.Target, store.AuditRecord, error) {
		created, err := m.AddGHRenderTarget("csrv", "o/r", "home-server", "PROD_ENV_FILE", keys)
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		return created, store.AuditRecord{
			Actor: "test", Action: "target.add", TargetID: created.ID, Details: "fixture",
			EventKind: store.KindTargetConfig, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, key, target
}

// renderServer answers the environment endpoints and records what was PUT.
func renderServer(t *testing.T) (*GHClient, *[]byte, *[32]byte, *[32]byte) {
	t.Helper()
	pub, priv, _ := box.GenerateKey(rand.Reader)
	var delivered []byte
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/environments/home-server/secrets/public-key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PublicKey{KeyID: "k", Key: base64.StdEncoding.EncodeToString(pub[:])})
	})
	mux.HandleFunc("PUT /repos/o/r/environments/home-server/secrets/PROD_ENV_FILE", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EncryptedValue string `json:"encrypted_value"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body.EncryptedValue)
		opened, ok := box.OpenAnonymous(nil, raw, pub, priv)
		if !ok {
			t.Error("delivered value did not open with the environment keypair")
		}
		delivered = opened
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /repos/o/r/environments/home-server/secrets/PROD_ENV_FILE", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	return c, &delivered, pub, priv
}

func TestPushRenderDeliversTheWholeFileAndRecordsItsKeys(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)

	res, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "in sync" {
		t.Fatalf("res = %+v", res)
	}
	if res.Environment != "home-server" {
		t.Fatalf("result does not carry the environment: %+v", res)
	}
	got := string(*delivered)
	if !strings.Contains(got, "ALPHA=a\n") || !strings.Contains(got, "BETA=b\n") {
		t.Fatalf("delivered blob = %q", got)
	}

	// The recorded key set is what the next push's shrink check reads.
	reloaded, err := st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := reloaded[0].PushedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "ALPHA,BETA" {
		t.Fatalf("recorded keys = %v", keys)
	}
	// Drift is answered by the blob's digest, so a target that has just pushed
	// the current values must read as in sync rather than as never-checked.
	if state := reloaded[0].GHState(nil, vault.ValueDigest(key, got)); state != "in sync" {
		t.Fatalf("state after push = %q", state)
	}
}

// The guard that makes signet safe in front of a live environment: a render
// that has lost keys since the last push must be refused, and must not have
// touched the destination on its way to being refused.
func TestPushRenderRefusesToDropKeysTheLastPushDelivered(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)

	if _, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman); err != nil {
		t.Fatal(err)
	}
	*delivered = nil

	// The target loses BETA from its key set while keeping the record of having
	// delivered it — the state the row holds after a key is detached from a
	// target that has already pushed.
	shrunk, err := st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	narrowed := shrunk[0]
	narrowed.Config = `{"repo":"o/r","secret_name":"PROD_ENV_FILE","environment":"home-server","keys":["ALPHA"]}`

	res, err := PushRender(context.Background(), st, key, gh, &narrowed, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "error" {
		t.Fatalf("a shrinking render was accepted: %+v", res)
	}
	if !strings.Contains(res.Err, "BETA") {
		t.Fatalf("refusal does not name the dropped key: %q", res.Err)
	}
	if *delivered != nil {
		t.Fatal("the destination was written before the push was refused")
	}

	// And the refusal is in the ledger, because it explains a stale environment
	// to whoever asks later.
	entries, err := st.ListAudit(50, "")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "sync.push.refused" && strings.Contains(e.Details, "BETA") {
			found = true
		}
	}
	if !found {
		t.Fatal("refusal was not recorded in the ledger")
	}
}

// A deliberate removal has to remain possible, or the guard becomes a wall.
func TestPushRenderAllowsAShrinkWhenAskedTo(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a", "BETA": "b"}
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA", "BETA"}, values)
	if _, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman); err != nil {
		t.Fatal(err)
	}
	*delivered = nil

	narrowed := *target
	narrowed.LastPushedKeys = `["ALPHA","BETA"]`
	narrowed.Config = `{"repo":"o/r","secret_name":"PROD_ENV_FILE","environment":"home-server","keys":["ALPHA"]}`
	res, err := PushRender(context.Background(), st, key, gh, &narrowed, values, RenderPushOptions{AllowShrink: true}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "in sync" {
		t.Fatalf("res = %+v", res)
	}
	if got := string(*delivered); strings.Contains(got, "BETA") {
		t.Fatalf("delivered blob still carries the dropped key: %q", got)
	}
}

// A push that cannot be completed must not be recorded as one — the target's
// state has to keep describing the last delivery that actually happened.
func TestPushRenderRefusalLeavesTheRecordedDeliveryAlone(t *testing.T) {
	gh, _, _, _ := renderServer(t)
	values := map[string]string{"ALPHA": "a"}
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA", "MISSING"}, values)

	res, err := PushRender(context.Background(), st, key, gh, target, values, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "error" || !strings.Contains(res.Err, "MISSING") {
		t.Fatalf("res = %+v", res)
	}
	reloaded, err := st.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded[0].LastPushedAt != "" {
		t.Fatalf("a refused push recorded a delivery time: %q", reloaded[0].LastPushedAt)
	}
	if keys, _ := reloaded[0].PushedKeys(); keys != nil {
		t.Fatalf("a refused push recorded a key set: %v", keys)
	}
}

// errorAs is errors.As without importing errors into every test above.
func errorAs[T error](err error, target *T) bool {
	for err != nil {
		if t, ok := err.(T); ok {
			*target = t
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// A target managing nothing renders to a header and no entries — a well-formed
// env file describing an environment with no configuration in it. Delivering
// that is the most destructive thing this code can do, and no guard downstream
// catches it: a first push has no baseline to shrink from.
func TestPushRenderRefusesATargetThatManagesNoKeys(t *testing.T) {
	gh, delivered, _, _ := renderServer(t)
	st, key, target := renderFixture(t, gh.BaseURL, nil, map[string]string{"ALPHA": "a"})

	res, err := PushRender(context.Background(), st, key, gh, target, map[string]string{"ALPHA": "a"},
		RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "error" {
		t.Fatalf("an empty render was delivered: %+v", res)
	}
	if !strings.Contains(res.Err, "manages no keys") {
		t.Fatalf("refusal does not explain itself: %q", res.Err)
	}
	if *delivered != nil {
		t.Fatalf("an empty environment was written to the destination: %q", string(*delivered))
	}
	// --allow-shrink is about deliberate removals, not about emptying an
	// environment wholesale, so it must not open this path either.
	res, err = PushRender(context.Background(), st, key, gh, target, map[string]string{"ALPHA": "a"},
		RenderPushOptions{AllowShrink: true}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "error" || *delivered != nil {
		t.Fatalf("--allow-shrink permitted an empty render: %+v / %q", res, string(*delivered))
	}
}

// The ledger is the only account of what reached a destination whose value can
// never be read back, and an environment is what makes two otherwise identical
// destinations different live secrets. Recording the scope but not the name
// wrote two of them down identically.
func TestASuccessfulRenderRecordsTheEnvironmentItWentTo(t *testing.T) {
	gh, _, _, _ := renderServer(t)
	st, key, target := renderFixture(t, gh.BaseURL, []string{"ALPHA"}, map[string]string{"ALPHA": "a"})

	res, err := PushRender(context.Background(), st, key, gh, target,
		map[string]string{"ALPHA": "a"}, RenderPushOptions{}, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "in sync" {
		t.Fatalf("push did not succeed: %+v", res)
	}
	if !strings.Contains(res.Dest, "home-server") {
		t.Fatalf("the result does not carry the environment: %q", res.Dest)
	}

	entries, err := st.ListAudit(50, "")
	if err != nil {
		t.Fatal(err)
	}
	var detail string
	for _, e := range entries {
		if e.Action == "sync.push" {
			detail = e.Details
		}
	}
	if detail == "" {
		t.Fatal("no sync.push entry in the ledger")
	}
	if !strings.Contains(detail, "home-server") {
		t.Fatalf("the ledger entry does not name the environment it wrote to: %q", detail)
	}
}
