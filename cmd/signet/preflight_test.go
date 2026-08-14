package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Einlanzerous/signet/internal/store"
	syncpkg "github.com/Einlanzerous/signet/internal/sync"
	"golang.org/x/crypto/nacl/box"
)

// fakeGitHub answers the Actions public-key endpoint per repo, so the CLI's
// preflight can be driven against every response GitHub really gives without
// talking to api.github.com. The client is what makes this reachable: these
// paths build no client of their own.
func fakeGitHub(t *testing.T, byRepo map[string]func(http.ResponseWriter)) *syncpkg.GHClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The write probe's reserved name must read as absent. The prefix match
		// below is deliberately broad, and left alone it answered the probe's
		// existence check with a public key — so every "reachable" test here was
		// driving the branch where preflight deletes a live secret, and passing.
		// A destination that is reachable for reads answers this with 404 and the
		// probe's delete then reports write access.
		if strings.HasSuffix(r.URL.Path, syncpkg.ProbeSecretName) {
			http.NotFound(w, r)
			return
		}
		for repo, respond := range byRepo {
			if strings.HasPrefix(r.URL.Path, "/repos/"+repo+"/") {
				respond(w)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := syncpkg.NewGHClient("tok")
	c.BaseURL = srv.URL
	return c
}

func reachable(t *testing.T) func(http.ResponseWriter) {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(map[string]string{
			"key_id": "k1", "key": base64.StdEncoding.EncodeToString(pub[:]),
		})
	}
}

func ungranted(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
}

func throttled(w http.ResponseWriter) {
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"message":"API rate limit exceeded"}`))
}

// captureStdout collects what a subcommand printed, so the report itself can be
// asserted rather than only the error it returned.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// seedGHTarget stores a secret and attaches a gh-actions destination, without
// preflighting: these tests are about what the check does, not the add.
func seedGHTarget(t *testing.T, project, name, repo string) {
	t.Helper()
	if err := runSet([]string{"--project", project, "--name", name, "--generate"}); err != nil {
		t.Fatal(err)
	}
	if err := runTargetAdd([]string{"--secret", project + "/" + name, "--gh-repo", repo, "--no-preflight"}); err != nil {
		t.Fatal(err)
	}
}

func vaultState(t *testing.T, st *store.Store) ([]store.Secret, []store.Target) {
	t.Helper()
	secrets, err := st.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := st.ListTargets()
	if err != nil {
		t.Fatal(err)
	}
	return secrets, targets
}

func TestSyncCheckPassesWhenEveryRepoIsReachable(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/one")
	seedGHTarget(t, "csrv", "OTHER", "o/two")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHub(t, map[string]func(http.ResponseWriter){
		"o/one": reachable(t), "o/two": reachable(t),
	})

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err != nil {
		t.Fatalf("all reachable but check failed: %v", err)
	}
	if !strings.Contains(out, "2 of 2 destinations reachable") {
		t.Fatalf("summary wrong: %q", out)
	}
}

func TestSyncCheckFailsOnAMissingGrant(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/granted")
	seedGHTarget(t, "csrv", "OTHER", "o/ungranted")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHub(t, map[string]func(http.ResponseWriter){
		"o/granted": reachable(t), "o/ungranted": ungranted,
	})

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err == nil {
		t.Fatal("an unreachable repo did not fail the check")
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("error does not count the unreachable repos: %v", err)
	}
	if !strings.Contains(out, "✗ o/ungranted") || !strings.Contains(out, "repository list") {
		t.Fatalf("report does not name the repo and the fix: %q", out)
	}
	if !strings.Contains(out, "✓ o/granted") {
		t.Fatalf("reachable repo not reported: %q", out)
	}
}

// A rate limit or a 5xx is not evidence against a grant, and AccessUnknown says
// so. Failing the run on it would make an unrelated GitHub hiccup look exactly
// like a misconfigured PAT — the confusion this feature exists to end.
func TestSyncCheckDoesNotFailOnAnInconclusiveProbe(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/throttled")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHub(t, map[string]func(http.ResponseWriter){"o/throttled": throttled})

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err != nil {
		t.Fatalf("an inconclusive probe failed the run: %v", err)
	}
	// Reported as its own state rather than as a pass or a failure.
	if !strings.Contains(out, "? o/throttled") || !strings.Contains(out, "1 inconclusive") {
		t.Fatalf("inconclusive probe not reported distinctly: %q", out)
	}
	if strings.Contains(out, "✗") {
		t.Fatalf("throttling reported as unreachable: %q", out)
	}
}

// A refused credential is the answer for every repository and about none of
// them, so the run stops and the message stays free of any repo name.
func TestSyncCheckStopsOnARefusedCredential(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/aaa")
	seedGHTarget(t, "csrv", "OTHER", "o/bbb")
	secrets, targets := vaultState(t, st)
	reject := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}
	gh := fakeGitHub(t, map[string]func(http.ResponseWriter){"o/aaa": reject, "o/bbb": reject})

	var err error
	captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err == nil {
		t.Fatal("a refused credential did not fail the check")
	}
	if !strings.Contains(err.Error(), "rejected the credential") {
		t.Fatalf("error does not name the credential: %v", err)
	}
	if strings.Contains(err.Error(), "o/aaa") || strings.Contains(err.Error(), "o/bbb") {
		t.Fatalf("credential failure blamed on a repository: %v", err)
	}
}

func TestSyncCheckWithNoDestinations(t *testing.T) {
	st := newCLIVault(t)
	if err := runSet([]string{"--project", "csrv", "--name", "LOCAL_ONLY", "--generate"}); err != nil {
		t.Fatal(err)
	}
	secrets, targets := vaultState(t, st)
	gh := fakeGitHub(t, nil)

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err != nil {
		t.Fatalf("nothing to check should not fail: %v", err)
	}
	if !strings.Contains(out, "no GitHub destinations") {
		t.Fatalf("unexpected output: %q", out)
	}
}

// The add-time preflight clears the way only when nothing is known against the
// repo. Blocked means the "run sync to push" line would be wrong; inconclusive
// and no-credential mean nothing was established either way.
func TestPreflightGHRepoClearsOnlyWhenNothingBlocks(t *testing.T) {
	cases := []struct {
		name    string
		respond func(http.ResponseWriter)
		want    bool
	}{
		{"reachable", reachable(t), true},
		{"no grant", ungranted, false},
		{"absent repo", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }, false},
		{"rate limited", throttled, true},
		{"server error", func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh := fakeGitHub(t, map[string]func(http.ResponseWriter){"o/r": tc.respond})
			if got := preflightGHRepo(gh, "o/r", ""); got != tc.want {
				t.Fatalf("clear = %v, want %v", got, tc.want)
			}
		})
	}

	// No credential resolved: nothing was asked, so nothing is known against it.
	if !preflightGHRepo(nil, "o/r", "") {
		t.Fatal("a skipped preflight should leave the path clear")
	}
}

// --no-preflight must not suppress the next step. Skipping the check is not the
// same as failing it, and this is the exact regression that shipped once.
func TestTargetAddNoPreflightStillPointsAtTheNextStep(t *testing.T) {
	newCLIVault(t)
	if err := runSet([]string{"--project", "csrv", "--name", "API_TOKEN", "--generate"}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runTargetAdd([]string{"--secret", "csrv/API_TOKEN", "--gh-repo", "o/r", "--no-preflight"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "target added") {
		t.Fatalf("add not reported: %q", out)
	}
	if !strings.Contains(out, "run `signet sync` to push") {
		t.Fatalf("--no-preflight suppressed the next step: %q", out)
	}
}

// fakeGitHubProbe answers reads for every repo and lets the test choose what the
// write probe's delete gets back per repo, which is the only variable the new
// syncCheck branches turn on.
func fakeGitHubProbe(t *testing.T, read map[string]func(http.ResponseWriter), deleteStatus map[string]int) *syncpkg.GHClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, syncpkg.ProbeSecretName) {
			// Absent on the existence check; the delete answers per repo.
			if r.Method == http.MethodDelete {
				for repo, status := range deleteStatus {
					if strings.HasPrefix(r.URL.Path, "/repos/"+repo+"/") {
						w.WriteHeader(status)
						return
					}
				}
			}
			http.NotFound(w, r)
			return
		}
		for repo, respond := range read {
			if strings.HasPrefix(r.URL.Path, "/repos/"+repo+"/") {
				respond(w)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := syncpkg.NewGHClient("tok")
	c.BaseURL = srv.URL
	return c
}

// The destination signet could read and not write is the one the live rollout
// hit. It has to be reported as blocking, with a fix that names write.
func TestSyncCheckReportsADestinationItCanReadButNotWrite(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/readonly")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHubProbe(t,
		map[string]func(http.ResponseWriter){"o/readonly": reachable(t)},
		map[string]int{"o/readonly": http.StatusForbidden},
	)

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err == nil {
		t.Fatal("a destination that will 403 the push passed the check")
	}
	if !strings.Contains(out, "✗ o/readonly") {
		t.Fatalf("read-only destination not reported as failing: %q", out)
	}
	if !strings.Contains(out, "write") {
		t.Fatalf("the report does not name the missing permission: %q", out)
	}
}

// An unsettled write probe is not a green destination: the half that decides
// whether a push lands is the half that went unanswered.
func TestSyncCheckCountsAnUnsettledWriteProbeAsInconclusive(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/flaky")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHubProbe(t,
		map[string]func(http.ResponseWriter){"o/flaky": reachable(t)},
		map[string]int{"o/flaky": http.StatusInternalServerError},
	)

	var err error
	out := captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err != nil {
		t.Fatalf("an inconclusive probe failed the run: %v", err)
	}
	if strings.Contains(out, "✓ o/flaky") {
		t.Fatalf("an unverified write was reported as reachable: %q", out)
	}
	if !strings.Contains(out, "? o/flaky") || !strings.Contains(out, "did not settle") {
		t.Fatalf("inconclusive destination not reported as such: %q", out)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("summary does not count it: %q", out)
	}
}

// A revoked credential is a fact about every destination. Landing a 401 from the
// write probe in the unsettled branch reported it as one readable destination
// among many and let the sweep continue.
func TestSyncCheckStopsWhenTheWriteProbeSaysTheCredentialIsRejected(t *testing.T) {
	st := newCLIVault(t)
	seedGHTarget(t, "csrv", "API_TOKEN", "o/one")
	secrets, targets := vaultState(t, st)
	gh := fakeGitHubProbe(t,
		map[string]func(http.ResponseWriter){"o/one": reachable(t)},
		map[string]int{"o/one": http.StatusUnauthorized},
	)

	var err error
	captureStdout(t, func() { err = syncCheck(gh, secrets, targets, nil) })
	if err == nil {
		t.Fatal("a rejected credential did not stop the check")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("the stop does not describe a credential problem: %v", err)
	}
}
