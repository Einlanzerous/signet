package api

import (
	"net/http"

	"github.com/Einlanzerous/signet/internal/version"
)

// healthzResponse is the body of `GET /healthz`.
//
// ── Why this grew a sha, and lost a "v" (SGNT-38) ──────────────────────────
//
// Switchyard's delivery reconciler polls this endpoint and records what is
// actually running — the observed half of the estate's delivery ledger (SWY-192
// defines the contract; SERV-128 owns the rollout). Signet is registered there
// as an ordinary first-party service even though it is a host daemon with no
// container: it binds the docker bridge deliberately, so the reconciler reaches
// it at `http://signet:4010/healthz` like anything else on construct_net.
//
// The field names and types are the contract, not a local choice:
//
//	version  bare semver ("1.9.0") or the literal "dev". Never a "v" prefix.
//	         Switchyard compares versions with strict equality, so the form has
//	         to match everywhere it is produced. Signet is a softer case than
//	         most — nothing REPORTS a host daemon, so there is no image label
//	         for a "v" to disagree with — but the same defect is live and
//	         harmful in amber, and an estate that gets this right in nine
//	         places and wrong in one is an estate where nobody trusts the rule.
//	sha      the full 40-char commit, or JSON null. Never abbreviated: the
//	         cross-service comparison is an equality test, not a prefix match.
//
// A struct rather than the previous map[string]string, because `sha` has to be
// able to marshal as null and a map of strings cannot express that.
type healthzResponse struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	SHA     *string `json:"sha"`
}

// handleHealthz answers the liveness probe and the build-identity contract.
//
// Deliberately unauthenticated, and the only route on this mux that is: every
// other handler goes through s.auth. The reconciler carries no credentials, and
// the body holds no secret — a version and a commit. It is also a plain function
// rather than a method because it reads nothing off the Server.
//
// There is only a 200 path. The contract permits a 503 and requires that it
// carry the SAME body shape — a degraded service is still running a version,
// and it is the one most worth identifying — so if a readiness verdict is ever
// added it belongs in this struct on both branches, not in a second shape.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	id := version.Get()
	writeJSON(w, http.StatusOK, healthzResponse{
		Status:  "ok",
		Version: id.Version,
		SHA:     id.SHA,
	})
}
