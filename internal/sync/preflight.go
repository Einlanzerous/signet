package sync

import (
	"context"
	"errors"
	"fmt"
)

// Reaching a repository's Actions secrets is a grant, not a fact about the
// credential: signet's PAT is fine-grained, so every new destination has to be
// added to the token's repository list by hand before a push can work. That is
// human-in-the-loop by design — signet cannot widen its own grant — which makes
// the only useful thing it can do say so early, and say what to do about it.
//
// Left alone the mistake surfaces at push time, per secret, as a raw 403 body
// that names neither the credential nor the fix.

// RepoAccess classifies what a probe established about the credential's reach.
type RepoAccess string

const (
	// AccessOK means the credential fetched the repo's sealing key, so the
	// repository is in its grant list and Actions secrets are readable.
	//
	// It does NOT prove the push will work. The sealing key needs fine-grained
	// Secrets: *read*; the PUT that delivers a secret needs read *and write*, and
	// GitHub offers no way to test a write without performing one. A repository
	// granted read-only therefore passes this probe and fails at push — which is
	// a narrower mistake than the one this exists to catch (a repository never
	// added at all), and one whose 403 still arrives explained.
	AccessOK RepoAccess = "ok"
	// AccessDenied means GitHub knows the repo but will not let this credential
	// touch its secrets — most often a fine-grained PAT with no grant on it.
	AccessDenied RepoAccess = "denied"
	// AccessMissing means the repo does not exist, or is private and invisible
	// to this credential. GitHub answers both with 404 on purpose.
	AccessMissing RepoAccess = "missing"
	// AccessRejected means the credential itself was refused: revoked, expired,
	// or malformed. It is not a fact about any repository.
	AccessRejected RepoAccess = "rejected"
	// AccessUnknown means the probe did not settle the question — a network
	// failure, a 5xx, or rate limiting. It is not evidence against the grant,
	// and callers must not treat it as one.
	AccessUnknown RepoAccess = "unknown"
)

// RepoProbe is one preflight's outcome: what the credential reached, the
// failure that decided it, and the operator-facing fix when signet can name
// one.
//
// It exists so that every caller — the CLI's `target add` and `sync --check`,
// and the API's add-target — answers the same probe the same way. They report
// through different media, but "is this blocking" and "what do I say about it"
// are one decision, and having made it twice is how they drifted apart.
type RepoProbe struct {
	Access RepoAccess
	Err    error
	// Hint is the fix, or "" when the failure is not one signet can attribute.
	Hint string
}

// Blocked reports positive evidence that a push to this repo will fail, as
// distinct from a probe that simply did not settle the question. Rate limits,
// 5xx, and network failures are not blocking: refusing to proceed on those
// would make an unrelated GitHub hiccup look like a misconfigured PAT.
func (p RepoProbe) Blocked() bool {
	switch p.Access {
	case AccessDenied, AccessMissing, AccessRejected:
		return true
	}
	return false
}

// Message is what to show for a probe that did not succeed: the fix when there
// is one, the transport error otherwise. Empty when the probe succeeded.
//
// It never returns "" for a failure, which is the property the callers rely on
// — an unattributable failure has to reach the operator as itself rather than
// being silently dropped for want of a hint.
func (p RepoProbe) Message() string {
	switch {
	case p.Err == nil:
		return ""
	case p.Hint != "":
		return p.Hint
	default:
		return p.Err.Error()
	}
}

// CheckRepoAccess asks whether the credential can manage repo's Actions
// secrets, classifying the answer and attaching the fix.
//
// It probes the repository's Actions public key: the cheapest read that needs a
// grant on the repo at all. Nothing secret is sent and nothing secret comes
// back — a repo sealing key is public by definition, and it is discarded here
// anyway. See AccessOK for what a pass does and does not prove.
func (c *GHClient) CheckRepoAccess(ctx context.Context, repo string) RepoProbe {
	_, _, err := c.RepoPublicKey(ctx, repo)
	if err == nil {
		return RepoProbe{Access: AccessOK}
	}
	return RepoProbe{Access: classifyAccess(err), Err: err, Hint: AccessHint(repo, err)}
}

// classifyAccess maps a failed Actions-secrets call to what it says about the
// credential's reach.
func classifyAccess(err error) RepoAccess {
	switch {
	case err == nil:
		return AccessOK
	case errors.Is(err, ErrForbidden):
		return AccessDenied
	case errors.Is(err, ErrNotFound):
		return AccessMissing
	case errors.Is(err, ErrUnauthorized):
		return AccessRejected
	default:
		return AccessUnknown
	}
}

// AccessHint returns the operator-facing fix for a failed Actions-secrets call
// against repo, or "" when signet cannot attribute the failure — in which case
// the raw error is the most honest thing to print, and callers should.
//
// The message is the whole point of the classification: a 403 body says
// "Resource not accessible by personal access token", which is true and leads
// nowhere. What is missing is that the repository has to be added to the
// token's grant list, and that only a person can do it.
//
// It names the likeliest cause without claiming to be the only one. A 403 is
// also how GitHub answers an archived repository, disabled Actions, and an org
// SAML or IP policy — so the hint accompanies the response rather than standing
// in for it, and callers are expected to show both.
func AccessHint(repo string, err error) string {
	switch classifyAccess(err) {
	case AccessDenied:
		return fmt.Sprintf("the GitHub credential cannot reach Actions Secrets on %s — usually the repository is missing from the fine-grained PAT's repository list (Secrets: read and write); an archived repo, disabled Actions, or an org SAML/IP policy answers the same 403", repo)
	case AccessMissing:
		return fmt.Sprintf("%s does not exist, or the GitHub credential cannot see it — check the owner/name, and that the repository is in the fine-grained PAT's repository list", repo)
	case AccessRejected:
		// Deliberately says nothing about repo: a refused credential is not a
		// fact about the repository that happened to be asked for, and framing
		// it as one sends the reader to check a grant that is beside the point.
		return "GitHub rejected the credential — the PAT is revoked, expired, or malformed; issue a new one and store it in the vault"
	case AccessUnknown:
		if errors.Is(err, ErrRateLimited) {
			return fmt.Sprintf("GitHub is rate-limiting this credential, so %s could not be checked — retry shortly; this says nothing about the repository's grant", repo)
		}
	}
	return ""
}
