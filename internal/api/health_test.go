package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Einlanzerous/signet/internal/version"
)

// What the delivery reconciler actually parses. Decoded into a raw map rather
// than into healthzResponse so this asserts the JSON *wire* shape — reusing the
// struct would make a renamed json tag invisible, which is exactly the break
// that would silently stop observations.
func decodeHealthz(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not JSON: %v (body=%s)", err, body)
	}
	return got
}

func TestHandleHealthzReportsBuildIdentity(t *testing.T) {
	origVersion, origCommit := version.Version, version.Commit
	t.Cleanup(func() { version.Version, version.Commit = origVersion, origCommit })

	const sha = "36b6412a1e8b0f4d9c7a2e5f8b3c1d0a9e6f4b2c"
	version.Version, version.Commit = "1.9.0", sha

	rec := httptest.NewRecorder()
	handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	got := decodeHealthz(t, rec.Body.Bytes())
	// The regression this test exists for: release.yml stamped `tag_name`
	// (`v1.9.0`) where it meant `version` (`1.9.0`), and the daemon reported the
	// prefixed form on /healthz for every release.
	if got["version"] != "1.9.0" {
		t.Errorf("version = %v, want bare semver 1.9.0 with no leading v", got["version"])
	}
	if got["sha"] != sha {
		t.Errorf("sha = %v, want the full 40-char commit %s", got["sha"], sha)
	}
	if got["status"] != "ok" {
		t.Errorf("status = %v, want ok", got["status"])
	}
}

// An unstamped build must say "dev", not a plausible-looking semver. The old
// package default was `0.1.0-dev`, which reads as a real version and would land
// in the delivery ledger as one.
func TestHandleHealthzUnstampedBuild(t *testing.T) {
	origVersion, origCommit := version.Version, version.Commit
	t.Cleanup(func() { version.Version, version.Commit = origVersion, origCommit })

	// Exactly what a build with no -X flags produces.
	version.Version, version.Commit = "", ""

	rec := httptest.NewRecorder()
	handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	got := decodeHealthz(t, rec.Body.Bytes())
	if got["version"] != "dev" {
		t.Errorf("version = %v, want dev — a blank ldflag must not report an empty version", got["version"])
	}
	if _, present := got["sha"]; !present {
		t.Error("sha key is missing; the contract wants it present and null")
	}
	if got["sha"] != nil {
		t.Errorf("sha = %v, want null", got["sha"])
	}
}

// /healthz is the ONE route on this mux that is unauthenticated, and it has to
// stay that way: the delivery reconciler carries no credentials, and every other
// handler goes through s.auth. A token requirement here reads as `unreachable`
// on the matrix for a daemon that is running perfectly well.
func TestHealthzIsUnauthenticated(t *testing.T) {
	s, err := New(nil, nil, nil, "a-token-that-is-set")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d with an API token configured, want 200", rec.Code)
	}
}
