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

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
	"golang.org/x/crypto/nacl/box"
)

// preflightServer answers the Actions public-key endpoint for every repo with
// the status registered for it, so one server can stand in for a PAT that
// reaches some repositories and not others.
func preflightServer(t *testing.T, byRepo map[string]func(http.ResponseWriter)) *GHClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for repo, respond := range byRepo {
			if r.URL.Path == "/repos/"+repo+"/actions/secrets/public-key" {
				respond(w)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	return c
}

func grantedRepo(t *testing.T) func(http.ResponseWriter) {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(PublicKey{KeyID: "k1", Key: base64.StdEncoding.EncodeToString(pub[:])})
	}
}

// The 403 GitHub actually returns for a repo missing from a fine-grained PAT's
// grant list.
func ungrantedRepo(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"message":"Resource not accessible by personal access token","documentation_url":"https://docs.github.com/rest"}`))
}

func TestPreflightClassifiesAccess(t *testing.T) {
	cases := []struct {
		name     string
		respond  func(http.ResponseWriter)
		want     RepoAccess
		wantHint string // substring the operator-facing message must carry
		// aboutRepo is false for causes that are about the credential rather
		// than the repository, whose message must not blame the repo.
		aboutRepo bool
	}{
		{
			name:     "granted",
			respond:  grantedRepo(t),
			want:     AccessOK,
			wantHint: "",
		},
		{
			name:      "not in the PAT's repository list",
			respond:   ungrantedRepo,
			want:      AccessDenied,
			wantHint:  "repository list",
			aboutRepo: true,
		},
		{
			name:      "repo absent or invisible",
			respond:   func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) },
			want:      AccessMissing,
			wantHint:  "does not exist",
			aboutRepo: true,
		},
		{
			name: "credential rejected",
			respond: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"message":"Bad credentials"}`))
			},
			want:     AccessRejected,
			wantHint: "revoked",
		},
		{
			// A throttled request is a 403 too. Reading it as a missing grant
			// would send an operator to edit a PAT that is already correct.
			name: "rate limited with a 403",
			respond: func(w http.ResponseWriter) {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			},
			want:      AccessUnknown,
			wantHint:  "rate-limiting",
			aboutRepo: true,
		},
		{
			name:     "server error settles nothing",
			respond:  func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
			want:     AccessUnknown,
			wantHint: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := preflightServer(t, map[string]func(http.ResponseWriter){"o/r": tc.respond})
			access, err := c.PreflightRepo(context.Background(), "o/r")
			if access != tc.want {
				t.Fatalf("access = %q, want %q (err %v)", access, tc.want, err)
			}
			hint := AccessHint("o/r", err)
			if tc.wantHint == "" {
				if hint != "" {
					t.Fatalf("unattributable failure produced a hint: %q", hint)
				}
				return
			}
			if !strings.Contains(hint, tc.wantHint) {
				t.Fatalf("hint %q does not mention %q", hint, tc.wantHint)
			}
			if got := strings.Contains(hint, "o/r"); got != tc.aboutRepo {
				t.Fatalf("hint %q names the repo = %v, want %v", hint, got, tc.aboutRepo)
			}
		})
	}
}

// The probe must stay a read of public material: nothing about the secret being
// synced may travel with a question about whether the repo is reachable.
func TestPreflightSendsNoSecretMaterial(t *testing.T) {
	var calls []string
	var bodies []int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		bodies = append(bodies, r.ContentLength)
		ungrantedRepo(w)
	}))
	defer srv.Close()
	c := NewGHClient("tok")
	c.BaseURL = srv.URL

	if _, err := c.PreflightRepo(context.Background(), "o/r"); err == nil {
		t.Fatal("403 preflight returned no error")
	}
	if len(calls) != 1 || calls[0] != "GET /repos/o/r/actions/secrets/public-key" {
		t.Fatalf("preflight made %v", calls)
	}
	if bodies[0] > 0 {
		t.Fatalf("preflight sent a %d-byte body", bodies[0])
	}
}

// PushSecret's failure has to carry the fix, and keep the transport detail: the
// operator needs the first, and the ledger records the second.
func TestPushSecretExplainsMissingGrant(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := vault.Encrypt(key, []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	sec, _, err := store.MutateValue(st, func(m *store.Mutation) (*store.Secret, store.AuditRecord, error) {
		s, err := m.CreateSecret("csrv", "API_TOKEN", "", false, "")
		if err != nil {
			return nil, store.AuditRecord{}, err
		}
		if _, err := m.AddVersion(s.ID, nonce, ct, vault.VersionHash(nonce, ct), "test"); err != nil {
			return nil, store.AuditRecord{}, err
		}
		if _, err := m.AddGHTarget(s.ID, "Einlanzerous/argosy", "API_TOKEN"); err != nil {
			return nil, store.AuditRecord{}, err
		}
		return s, store.AuditRecord{
			Actor: "test", Action: "secret.set", SecretID: s.ID, Details: "fixture",
			EventKind: store.KindSecretWrite, ActorRole: store.RoleHuman,
			Status: &store.AuditStatus{Outcome: store.OutcomeCreated},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	gh := preflightServer(t, map[string]func(http.ResponseWriter){"Einlanzerous/argosy": ungrantedRepo})
	results, err := PushSecret(context.Background(), st, key, gh, sec, "test", store.RoleHuman)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != "error" {
		t.Fatalf("results = %+v", results)
	}
	if !strings.Contains(results[0].Hint, "Einlanzerous/argosy") ||
		!strings.Contains(results[0].Hint, "Secrets: read and write") {
		t.Fatalf("hint does not name the fix: %q", results[0].Hint)
	}
	// The raw body stays on the result and, through it, in the ledger entry the
	// failed push wrote. The hint is an addition, not a replacement.
	if !strings.Contains(results[0].Err, "403") {
		t.Fatalf("transport detail lost: %q", results[0].Err)
	}
	entries, err := st.ListAudit(50, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	var recorded bool
	for _, e := range entries {
		if e.Action == "sync.push.failed" && strings.Contains(e.Details, "Resource not accessible") {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("ledger has no sync.push.failed entry carrying the GitHub body")
	}
}
