package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
)

// blobValues parses a delivered blob into key→value. Asserting on parsed pairs
// rather than on raw "KEY=value" substrings keeps these tests independent of the
// renderer's quoting, and keeps assignment syntax out of the source, where
// secret scanners read it as a credential regardless of the placeholder value.
func blobValues(t *testing.T, blob string) map[string]string {
	t.Helper()
	pairs, err := envfile.Parse(strings.NewReader(blob))
	if err != nil {
		t.Fatalf("parse delivered blob %q: %v", blob, err)
	}
	return envfile.Map(pairs)
}

func seedRenderTarget(t *testing.T, st *store.Store, project, repo, env, secretName string, keys []string) *store.Target {
	t.Helper()
	var tgt *store.Target
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		added, err := m.AddGHRenderTarget(project, repo, env, secretName, keys)
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

// envGHServer answers the environment endpoints and records the blobs PUT to
// them, so a test can assert on what a push actually delivered.
func envGHServer(t *testing.T, repo, env, secretName string) (*syncpkg.GHClient, *[]string) {
	t.Helper()
	pub, priv, _ := box.GenerateKey(rand.Reader)
	var delivered []string
	base := "/repos/" + repo + "/environments/" + env + "/secrets/"
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"public-key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(syncpkg.PublicKey{KeyID: "k", Key: base64.StdEncoding.EncodeToString(pub[:])})
	})
	mux.HandleFunc("PUT "+base+secretName, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EncryptedValue string `json:"encrypted_value"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body.EncryptedValue)
		opened, ok := box.OpenAnonymous(nil, raw, pub, priv)
		if !ok {
			t.Error("delivered value did not open with the environment keypair")
		}
		delivered = append(delivered, string(opened))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET "+base+secretName, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := syncpkg.NewGHClient("tok")
	c.BaseURL = srv.URL
	return c, &delivered
}

// The mirror explains vault state without the master key, so a destination that
// differs from another only by its environment has to be distinguishable — and
// a rendered target has to appear at all.
func TestMirrorPublishesEnvironmentScopeAndRenderedTargets(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "TOKEN", true)
	seedVersion(t, st, sec.ID, key, "value", store.Minted)
	seedGHTarget(t, st, sec.ID, "o/r", "TOKEN")
	if _, err := st.Mutate(func(m *store.Mutation) (store.AuditRecord, error) {
		if _, err := m.AddGHTarget(sec.ID, "o/r", "home-server", "TOKEN"); err != nil {
			return store.AuditRecord{}, err
		}
		return fixtureRecord("target.add", store.KindTargetConfig), nil
	}); err != nil {
		t.Fatal(err)
	}
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"TOKEN"})

	view := secretDetail(t, srv, "csrv", "TOKEN")

	var repoScoped, envScoped, rendered *TargetView
	for i := range view.Targets {
		tv := &view.Targets[i]
		switch {
		case tv.Kind == "gh-render":
			rendered = tv
		case tv.Kind == "gh-actions" && tv.Environment == "":
			repoScoped = tv
		case tv.Kind == "gh-actions" && tv.Environment == "home-server":
			envScoped = tv
		}
	}
	if repoScoped == nil || envScoped == nil {
		t.Fatalf("the two gh-actions scopes are not distinguishable: %+v", view.Targets)
	}
	if rendered == nil {
		t.Fatalf("rendered target missing from the mirror: %+v", view.Targets)
	}
	if rendered.SecretName != "PROD_ENV_FILE" || rendered.Environment != "home-server" {
		t.Fatalf("rendered target = %+v", rendered)
	}
	// The blob is one opaque value at the destination, so the key count is the
	// only measure of it a blind mirror can publish.
	if rendered.KeyCount != 1 {
		t.Fatalf("rendered target key count = %d", rendered.KeyCount)
	}
	if rendered.State != "never" {
		t.Fatalf("rendered target state = %q", rendered.State)
	}
}

// A key the vault cannot supply makes the next push a refusal, not a late
// delivery, so the mirror must not report it as ordinary drift.
func TestMirrorReportsAnIncompleteRenderAsIncomplete(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "TOKEN", true)
	seedVersion(t, st, sec.ID, key, "value", store.Minted)
	// PENDING exists but has no version — the state every secret passes through.
	seedSecret(t, st, "csrv", "PENDING", true)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"TOKEN", "PENDING"})

	view := secretDetail(t, srv, "csrv", "TOKEN")
	var seen bool
	for _, tv := range view.Targets {
		if tv.Kind != "gh-render" {
			continue
		}
		seen = true
		if tv.State != "incomplete" {
			t.Fatalf("rendered target state = %q, want incomplete", tv.State)
		}
	}
	if !seen {
		t.Fatalf("no rendered target in the view: %+v", view.Targets)
	}
}

// secretDetail reads one secret's mirror view out of the detail endpoint's
// envelope. Unmarshalling the body straight into a SecretView silently yields a
// zero value — every assertion on its targets then passes against nothing.
func secretDetail(t *testing.T, srv *Server, project, name string) SecretView {
	t.Helper()
	rec := get(t, srv.Handler(), "/v1/mirror/secrets/"+project+"/"+name, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("mirror: %d — %s", rec.Code, rec.Body)
	}
	var body struct {
		Secret *SecretView `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Secret == nil {
		t.Fatalf("no secret %s/%s in the mirror response: %s", project, name, rec.Body)
	}
	return *body.Secret
}

// Syncing one secret through the mirror has to carry the environment file that
// also contains it. Otherwise a rotation updates the secret's own destinations
// and leaves PROD_ENV_FILE holding the old value — the drift this target kind
// exists to end, arriving through a different door.
func TestSyncCommandAlsoDeliversTheRenderedTargetCarryingTheSecret(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "TOKEN", true)
	seedVersion(t, st, sec.ID, key, "rotated-value", store.Minted)
	other := seedSecret(t, st, "csrv", "OTHER", true)
	seedVersion(t, st, other.ID, key, "other-value", store.Minted)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"TOKEN", "OTHER"})

	gh, delivered := envGHServer(t, "o/r", "home-server", "PROD_ENV_FILE")
	srv.gh = gh

	rec := postCmd(t, srv.Handler(), "/v1/commands/sync", `{"project":"csrv","name":"TOKEN"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync: %d — %s", rec.Code, rec.Body)
	}
	if len(*delivered) != 1 {
		t.Fatalf("rendered target was delivered %d times", len(*delivered))
	}
	got := blobValues(t, (*delivered)[0])
	if got["TOKEN"] != "rotated-value" {
		t.Fatalf("delivered blob does not carry the rotated value: %#v", got)
	}
	// The whole file goes, not just the secret that triggered the sync.
	if got["OTHER"] != "other-value" {
		t.Fatalf("delivered blob is not the whole file: %#v", got)
	}

	var body struct {
		Results []syncpkg.PushResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var sawRender bool
	for _, r := range body.Results {
		if r.Secret == "PROD_ENV_FILE" {
			sawRender = true
			if r.State != "in sync" || r.Environment != "home-server" {
				t.Fatalf("render result = %+v", r)
			}
		}
	}
	if !sawRender {
		t.Fatalf("the response does not report the rendered push: %+v", body.Results)
	}
}

// A secret the render does not carry must not trigger one — a push to a live
// environment is not something to do on the strength of sharing a project.
func TestSyncCommandLeavesUnrelatedRenderedTargetsAlone(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "UNMANAGED", true)
	seedVersion(t, st, sec.ID, key, "value", store.Minted)
	managed := seedSecret(t, st, "csrv", "TOKEN", true)
	seedVersion(t, st, managed.ID, key, "value", store.Minted)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"TOKEN"})

	gh, delivered := envGHServer(t, "o/r", "home-server", "PROD_ENV_FILE")
	srv.gh = gh

	rec := postCmd(t, srv.Handler(), "/v1/commands/sync", `{"project":"csrv","name":"UNMANAGED"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync: %d — %s", rec.Code, rec.Body)
	}
	if len(*delivered) != 0 {
		t.Fatalf("a secret the render does not carry pushed it anyway: %v", *delivered)
	}
}

// The environment is part of a destination's identity, so add-target must not
// mistake an environment-scoped destination for a duplicate of the
// repository-scoped one with the same name.
func TestAddTargetTreatsAnEnvironmentAsADistinctDestination(t *testing.T) {
	srv, st, _, _ := testServer(t)
	seedSecret(t, st, "csrv", "TOKEN", true)

	rec := postCmd(t, srv.Handler(), "/v1/commands/add-target", `{"project":"csrv","name":"TOKEN","repo":"o/r"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("repository-scoped add: %d — %s", rec.Code, rec.Body)
	}
	rec = postCmd(t, srv.Handler(), "/v1/commands/add-target",
		`{"project":"csrv","name":"TOKEN","repo":"o/r","environment":"home-server"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("environment-scoped add was refused as a duplicate: %d — %s", rec.Code, rec.Body)
	}
	var body struct {
		Target TargetView `json:"target"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Target.Environment != "home-server" {
		t.Fatalf("response does not carry the environment: %+v", body.Target)
	}

	// The same environment twice is a duplicate, though.
	rec = postCmd(t, srv.Handler(), "/v1/commands/add-target",
		`{"project":"csrv","name":"TOKEN","repo":"o/r","environment":"home-server"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a genuine duplicate was accepted: %d — %s", rec.Code, rec.Body)
	}
}

// Rotating through the mirror has to carry the rendered blob too. Without it
// the response says {"rotated": true} while the environment goes on serving the
// credential the vault has just replaced — and nothing reports a problem,
// because the destination's value can never be read back.
func TestRotateCommandAlsoDeliversTheRenderedTargetCarryingTheSecret(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "DB_PASSWORD", true)
	seedVersion(t, st, sec.ID, key, "old-value", store.Minted)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"DB_PASSWORD"})

	gh, delivered := envGHServer(t, "o/r", "home-server", "PROD_ENV_FILE")
	srv.gh = gh

	rec := postCmd(t, srv.Handler(), "/v1/commands/rotate", `{"project":"csrv","name":"DB_PASSWORD"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d — %s", rec.Code, rec.Body)
	}
	if len(*delivered) != 1 {
		t.Fatalf("the rendered target was delivered %d times on rotate", len(*delivered))
	}
	got := blobValues(t, (*delivered)[0])
	rotated, ok := got["DB_PASSWORD"]
	if !ok {
		t.Fatalf("the blob does not carry the key at all: %#v", got)
	}
	if rotated == "old-value" {
		t.Fatalf("the blob still carries the pre-rotation value: %#v", got)
	}

	var body struct {
		Rotated bool                 `json:"rotated"`
		FanOut  []syncpkg.PushResult `json:"fan_out"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Rotated {
		t.Fatal("rotate reported failure")
	}
	var sawRender bool
	for _, r := range body.FanOut {
		if r.Secret == "PROD_ENV_FILE" && r.State == "in sync" {
			sawRender = true
		}
	}
	if !sawRender {
		t.Fatalf("the rotate response does not report the rendered push: %+v", body.FanOut)
	}
}

// The mirror is the surface Switchyard reads, so it is the one that can least
// afford to name the wrong fix: a target with no keys wants keys attached, not
// a value set.
func TestMirrorDistinguishesAnEmptyRenderFromAnIncompleteOne(t *testing.T) {
	srv, st, key, _ := testServer(t)
	sec := seedSecret(t, st, "csrv", "TOKEN", true)
	seedVersion(t, st, sec.ID, key, "value", store.Minted)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "EMPTY_FILE", nil)
	seedRenderTarget(t, st, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"TOKEN"})

	views, err := srv.buildViews()
	if err != nil {
		t.Fatal(err)
	}
	var csrv *ProjectView
	for i := range views {
		if views[i].Project == "csrv" {
			csrv = &views[i]
		}
	}
	if csrv == nil {
		t.Fatal("no view for project csrv")
	}
	// Asserted on the project's rendered targets rather than on a secret's,
	// because the empty one carries no keys and so annotates no secret. Looking
	// for it there is what made the previous version of this test pass without
	// ever finding it.
	states := map[string]string{}
	for _, tv := range csrv.Renders {
		states[tv.SecretName] = tv.State
	}
	if got, ok := states["EMPTY_FILE"]; !ok {
		t.Fatalf("the empty rendered target is absent from the mirror: %+v", csrv.Renders)
	} else if got != "empty" {
		t.Fatalf("empty render reported as %q, which names the wrong fix", got)
	}
	// The other target manages a key that resolves, so it must not be swept into
	// the same state: the distinction is the point of the test.
	if got := states["PROD_ENV_FILE"]; got == "empty" || got == "incomplete" {
		t.Fatalf("a complete render reported as %q", got)
	}
}
