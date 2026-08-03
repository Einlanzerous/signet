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

// RepoAccess classifies whether the sync credential can manage a repository's
// Actions secrets.
type RepoAccess string

const (
	// AccessOK means the credential fetched the repo's sealing key: it can read
	// and, by the same grant, write that repo's Actions secrets.
	AccessOK RepoAccess = "ok"
	// AccessDenied means GitHub knows the repo but will not let this credential
	// touch its secrets — the fine-grained PAT has no grant on it.
	AccessDenied RepoAccess = "denied"
	// AccessMissing means the repo does not exist, or is private and invisible
	// to this credential. GitHub answers both with 404 on purpose.
	AccessMissing RepoAccess = "missing"
	// AccessRejected means the credential itself was refused: revoked, expired,
	// or malformed.
	AccessRejected RepoAccess = "rejected"
	// AccessUnknown means the probe did not settle the question — a network
	// failure, a 5xx, or rate limiting. It is not evidence against the grant.
	AccessUnknown RepoAccess = "unknown"
)

// PreflightRepo asks whether the credential can manage repo's Actions secrets,
// and returns the underlying failure alongside the classification so a caller
// can report the transport detail as well as the cause.
//
// It probes the repository's Actions public key: the cheapest read that needs
// the same grant a push does. Nothing secret is sent and nothing secret comes
// back — a repo sealing key is public by definition, and it is discarded here
// anyway.
func (c *GHClient) PreflightRepo(ctx context.Context, repo string) (RepoAccess, error) {
	_, _, err := c.RepoPublicKey(ctx, repo)
	if err == nil {
		return AccessOK, nil
	}
	return classifyAccess(err), err
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
func AccessHint(repo string, err error) string {
	switch classifyAccess(err) {
	case AccessDenied:
		return fmt.Sprintf("the GitHub credential has no Actions Secrets access to %s — add the repository to the fine-grained PAT's repository list with Secrets: read and write, then re-run", repo)
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
