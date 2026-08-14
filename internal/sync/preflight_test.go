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
			probe := c.CheckRepoAccess(context.Background(), "o/r", "")
			if probe.Access != tc.want {
				t.Fatalf("access = %q, want %q (err %v)", probe.Access, tc.want, probe.Err)
			}
			// Only positive evidence may block: an inconclusive probe that failed
			// a run would turn a rate limit into a report of a broken grant.
			wantBlocked := tc.want == AccessDenied || tc.want == AccessMissing || tc.want == AccessRejected
			if probe.Blocked() != wantBlocked {
				t.Fatalf("%q blocked = %v, want %v", tc.want, probe.Blocked(), wantBlocked)
			}
			// Every failure reaches the operator, hint or no hint. A probe that
			// failed for a reason signet cannot name is still a failure.
			if tc.want == AccessOK {
				if probe.Message() != "" {
					t.Fatalf("successful probe produced a message: %q", probe.Message())
				}
				return
			}
			if probe.Message() == "" {
				t.Fatal("failed probe produced no message at all")
			}
			if tc.wantHint == "" {
				if probe.Hint != "" {
					t.Fatalf("unattributable failure produced a hint: %q", probe.Hint)
				}
				if probe.Message() != probe.Err.Error() {
					t.Fatalf("unattributable failure did not fall back to the error: %q", probe.Message())
				}
				return
			}
			if !strings.Contains(probe.Hint, tc.wantHint) {
				t.Fatalf("hint %q does not mention %q", probe.Hint, tc.wantHint)
			}
			if got := strings.Contains(probe.Hint, "o/r"); got != tc.aboutRepo {
				t.Fatalf("hint %q names the repo = %v, want %v", probe.Hint, got, tc.aboutRepo)
			}
		})
	}
}

// GitHub answers a secondary rate limit with 403, a non-zero remaining count,
// and often no Retry-After — the headers alone cannot tell it from a repo
// missing from the PAT's grant list, and telling someone to edit a correct PAT
// is the one outcome this feature exists to prevent.
func TestSecondaryRateLimitIsNotReadAsAMissingGrant(t *testing.T) {
	c := preflightServer(t, map[string]func(http.ResponseWriter){
		"o/r": func(w http.ResponseWriter) {
			w.Header().Set("X-RateLimit-Remaining", "4998") // nowhere near exhausted
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`))
		},
	})
	probe := c.CheckRepoAccess(context.Background(), "o/r", "")
	if probe.Access != AccessUnknown {
		t.Fatalf("secondary rate limit classified as %q", probe.Access)
	}
	if probe.Blocked() {
		t.Fatal("a throttled request must not block the run")
	}
	if strings.Contains(probe.Message(), "repository list") {
		t.Fatalf("throttling reported as a grant problem: %q", probe.Message())
	}
}

// A 404 has to carry what GitHub said as much as any other failure: it is the
// ledger's only durable record, and "not found" alone leaves no way to tell a
// typo from a revoked grant.
func TestNotFoundKeepsTheResponse(t *testing.T) {
	c := preflightServer(t, map[string]func(http.ResponseWriter){
		"o/r": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`))
		},
	})
	probe := c.CheckRepoAccess(context.Background(), "o/r", "")
	if probe.Access != AccessMissing {
		t.Fatalf("access = %q", probe.Access)
	}
	if !strings.Contains(probe.Err.Error(), "404") ||
		!strings.Contains(probe.Err.Error(), "documentation_url") {
		t.Fatalf("404 dropped the status line or body: %q", probe.Err)
	}
}

// A read-only grant is caught by the probe, not left for the push to discover.
//
// This test used to assert the opposite — that a read-only grant passed
// preflight, justified by a comment saying GitHub offered no way to test a
// write without performing one. That was the bug, written down as an
// expectation; SGNT-29 removed it. It is kept pointing the other way so a
// revert has something to fail against, and it still checks that the push
// explains itself, because preflight is skippable and a push is not.
func TestReadOnlyGrantIsCaughtByPreflightNotByThePush(t *testing.T) {
	read := grantedRepo(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/actions/secrets/public-key", func(w http.ResponseWriter, r *http.Request) {
		read(w)
	})
	// The reserved name is absent, which is what licenses the delete.
	mux.HandleFunc("GET /repos/o/r/actions/secrets/"+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	// Read granted, write not: the probe delete is refused exactly as the live
	// environment refused it.
	mux.HandleFunc("DELETE /repos/o/r/actions/secrets/"+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		ungrantedRepo(w)
	})
	mux.HandleFunc("PUT /repos/o/r/actions/secrets/TOKEN", func(w http.ResponseWriter, r *http.Request) {
		ungrantedRepo(w)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewGHClient("tok")
	c.BaseURL = srv.URL

	probe := c.CheckRepoAccess(context.Background(), "o/r", "")
	if probe.Access != AccessReadOnly {
		t.Fatalf("a read-only grant probed as %q — the false green is back", probe.Access)
	}
	if !probe.Blocked() {
		t.Fatal("a destination that will 403 the push was not reported as blocking")
	}
	if !strings.Contains(probe.Message(), "read") || !strings.Contains(probe.Message(), "write") {
		t.Fatalf("the fix does not name both halves of the grant: %q", probe.Message())
	}

	// And the push still explains itself, since --no-preflight exists.
	_, err := c.PutSecret(context.Background(), "o/r", "", "TOKEN", "c2VhbGVk", "k1")
	if err == nil {
		t.Fatal("write to a read-only grant succeeded")
	}
	if hint := AccessHint("o/r", "", err); !strings.Contains(hint, "read and write") {
		t.Fatalf("push hint does not name the write permission: %q", hint)
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

	if probe := c.CheckRepoAccess(context.Background(), "o/r", ""); probe.Err == nil {
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
		if _, err := m.AddVersion(s.ID, nonce, ct, vault.VersionHash(nonce, ct), "test", store.Minted); err != nil {
			return nil, store.AuditRecord{}, err
		}
		if _, err := m.AddGHTarget(s.ID, "Einlanzerous/argosy", "", "API_TOKEN"); err != nil {
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

// preflightWriteServer answers the read probe through the same grantedRepo
// helper the other tests use, and lets the test decide what the write probe
// gets back — that status is the whole variable under test.
//
// probeExists controls whether the reserved name is reported as present, which
// is the case where the probe must decline to delete rather than proceed.
func preflightWriteServer(t *testing.T, deleteStatus int, probeExists bool) *GHClient {
	t.Helper()
	read := grantedRepo(t)
	base := "/repos/o/r/environments/home-server/secrets/"
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"public-key", func(w http.ResponseWriter, r *http.Request) {
		read(w)
	})
	mux.HandleFunc("GET "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		if !probeExists {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(SecretMeta{Name: ProbeSecretName, UpdatedAt: "2026-08-01T00:00:00Z"})
	})
	mux.HandleFunc("DELETE "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(deleteStatus)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewGHClient("tok")
	c.BaseURL = srv.URL
	return c
}

// The live failure this exists for: a credential that can read an environment
// and not write it passed preflight, then 403'd on the PUT. Reading is not a
// proxy for writing, and at environment scope they are separate grants.
func TestPreflightCatchesAReadableDestinationItCannotWrite(t *testing.T) {
	c := preflightWriteServer(t, http.StatusForbidden, false)

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if probe.Access != AccessReadOnly {
		t.Fatalf("a destination that refuses writes probed as %q", probe.Access)
	}
	if probe.Write != WriteDenied {
		t.Fatalf("write = %q", probe.Write)
	}
	if !probe.Blocked() {
		t.Fatal("a destination that will 403 the push is not reported as blocking")
	}
	// The fix has to name write, because read is what the operator already
	// granted — the previous message sent them to exactly that setting.
	if !strings.Contains(probe.Message(), "write") {
		t.Fatalf("the hint does not name the missing permission: %q", probe.Message())
	}
	if !strings.Contains(probe.Message(), "Environments") {
		t.Fatalf("the hint does not name the environment permission: %q", probe.Message())
	}
}

// The pass: the delete was authorized and found nothing to delete. 404 is the
// evidence of write access, which is the inference this rests on.
func TestPreflightAcceptsADestinationItCanWrite(t *testing.T) {
	c := preflightWriteServer(t, http.StatusNotFound, false)

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if probe.Access != AccessOK || probe.Write != WriteOK {
		t.Fatalf("a writable destination probed as %q/%q", probe.Access, probe.Write)
	}
	if probe.Blocked() {
		t.Fatal("a writable destination reported as blocking")
	}
}

// An unsettled write probe must not read as either answer. Reporting it as
// reachable would reintroduce the false green through the back door.
func TestPreflightDoesNotGuessWhenTheWriteProbeIsInconclusive(t *testing.T) {
	c := preflightWriteServer(t, http.StatusInternalServerError, false)

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if probe.Write != WriteUnknown {
		t.Fatalf("an unsettled write probe resolved to %q", probe.Write)
	}
	if probe.Blocked() {
		t.Fatal("an inconclusive probe was treated as evidence against the grant")
	}
}

// The probe must never write. A delete is the only verb it may use, and only
// against a name that cannot exist.
func TestWriteProbeSendsOnlyADeleteOfTheReservedName(t *testing.T) {
	var seen []string
	pub, _, _ := box.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		// The reserved name must read as absent, or the probe correctly declines
		// to delete it and this test would be asserting against a no-op.
		if strings.HasSuffix(r.URL.Path, ProbeSecretName) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(PublicKey{KeyID: "k", Key: base64.StdEncoding.EncodeToString(pub[:])})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewGHClient("tok")
	c.BaseURL = srv.URL

	c.CheckRepoAccess(context.Background(), "o/r", "")
	for _, call := range seen {
		if strings.HasPrefix(call, "PUT ") || strings.HasPrefix(call, "POST ") {
			t.Fatalf("preflight performed a write: %s", call)
		}
	}
	want := "DELETE /repos/o/r/actions/secrets/" + ProbeSecretName
	var found bool
	for _, call := range seen {
		if call == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("write probe did not delete the reserved name: %v", seen)
	}
}

// A 401 on the write probe is a fact about the credential, not about one
// destination. Landing it in the unsettled branch reported the destination as
// readable and let a sweep continue against a revoked token, printing a wall of
// inconclusive lines instead of one stop.
func TestRejectedCredentialOnTheWriteProbeIsNotReportedAsReadable(t *testing.T) {
	c := preflightWriteServer(t, http.StatusUnauthorized, false)

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if probe.Access != AccessRejected {
		t.Fatalf("a 401 on the write probe classified as %q", probe.Access)
	}
	if !probe.Blocked() {
		t.Fatal("a rejected credential did not block")
	}
	if !strings.Contains(probe.Message(), "revoked") {
		t.Fatalf("message does not describe a credential problem: %q", probe.Message())
	}
}

// The probe must never destroy a secret. If the reserved name is present, the
// delete is not issued at all — the guarantee is the ordering, not the belief
// that the name cannot exist.
func TestWriteProbeDeclinesToDeleteAnExistingSecret(t *testing.T) {
	var deleted bool
	read := grantedRepo(t)
	base := "/repos/o/r/environments/home-server/secrets/"
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"public-key", func(w http.ResponseWriter, r *http.Request) { read(w) })
	mux.HandleFunc("GET "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SecretMeta{Name: ProbeSecretName, UpdatedAt: "2026-08-01T00:00:00Z"})
	})
	mux.HandleFunc("DELETE "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewGHClient("tok")
	c.BaseURL = srv.URL

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if deleted {
		t.Fatal("preflight deleted a secret that already existed")
	}
	if probe.Write != WriteUnknown {
		t.Fatalf("declining to probe resolved to %q rather than leaving the question open", probe.Write)
	}
	// It must say so rather than passing quietly: an unprobed destination that
	// reads as verified is the whole failure class.
	if !strings.Contains(probe.Message(), ProbeSecretName) {
		t.Fatalf("the operator is not told why the write was not established: %q", probe.Message())
	}
}

// A pass that performed a delete has to reach the operator. Message() keyed on
// Err alone returned "" here, and both CLI callers gate on Message().
func TestAPassThatDeletedSomethingStillReportsIt(t *testing.T) {
	// Absent at the existence check, present by the delete: the mid-probe race.
	c := preflightWriteServer(t, http.StatusNoContent, false)

	probe := c.CheckRepoAccess(context.Background(), "o/r", "home-server")
	if probe.Access != AccessOK || probe.Write != WriteOK {
		t.Fatalf("access = %q write = %q", probe.Access, probe.Write)
	}
	if probe.Message() == "" {
		t.Fatal("a probe that deleted a secret reported nothing")
	}
	if !strings.Contains(probe.Message(), "deleted") {
		t.Fatalf("the message does not say what happened: %q", probe.Message())
	}
}

// Go's default redirect policy rewrites DELETE to GET across a 301, which on a
// renamed repository would score a read as write access.
func TestWriteProbeDoesNotFollowARedirectIntoAGet(t *testing.T) {
	read := grantedRepo(t)
	base := "/repos/o/r/actions/secrets/"
	var methods []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"public-key", func(w http.ResponseWriter, r *http.Request) { read(w) })
	mux.HandleFunc("GET "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("DELETE "+base+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/repos/o/renamed/actions/secrets/"+ProbeSecretName, http.StatusMovedPermanently)
	})
	// Where the redirect would land. A GET here would 404 and look like a pass.
	mux.HandleFunc("/repos/o/renamed/actions/secrets/"+ProbeSecretName, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewGHClient("tok")
	c.BaseURL = srv.URL

	probe := c.CheckRepoAccess(context.Background(), "o/r", "")
	for _, m := range methods {
		if m == http.MethodGet {
			t.Fatal("the write probe was followed into a GET and would score a read as write access")
		}
	}
	if probe.Write == WriteOK {
		t.Fatalf("a 301 was scored as write access: %+v", probe)
	}
}
