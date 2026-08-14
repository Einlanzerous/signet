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
	// AccessOK means the credential fetched the destination's sealing key *and*
	// is permitted to write secrets there — both halves of what a push needs.
	//
	// This used to mean only the first half. The comment here said GitHub
	// offered no way to test a write without performing one, so the read was
	// accepted as a proxy for both; a live rollout then passed preflight against
	// an environment it could read and 403'd on the PUT. CanWriteSecret tests
	// the write directly and without writing, which is what makes this state
	// mean what its callers always read it as meaning.
	AccessOK RepoAccess = "ok"
	// AccessReadOnly means the credential can read this destination but may not
	// write secrets to it: the grant covers Secrets: read and not write, or —
	// at environment scope — Environments: read and not write. A push will 403.
	AccessReadOnly RepoAccess = "read-only"
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

// WriteAccess is what a write probe established about the credential's ability
// to deliver a secret to a destination it can already read.
type WriteAccess string

const (
	// WriteOK means a write was authorized — the delete probe got as far as
	// being told there was nothing to delete.
	WriteOK WriteAccess = "ok"
	// WriteDenied means the credential may read this destination and not write
	// it. This is the state that produces a 403 at push time.
	WriteDenied WriteAccess = "denied"
	// WriteUnknown means the probe did not settle the question — a network
	// failure, a 5xx, or rate limiting. Like AccessUnknown it is not evidence
	// against the grant, and must not be reported as one.
	WriteUnknown WriteAccess = "unknown"
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
	// Write is what the write probe established, and is only meaningful when
	// the read probe passed — there is nothing to ask about a destination the
	// credential cannot reach at all.
	Write WriteAccess
}

// Blocked reports positive evidence that a push to this repo will fail, as
// distinct from a probe that simply did not settle the question. Rate limits,
// 5xx, and network failures are not blocking: refusing to proceed on those
// would make an unrelated GitHub hiccup look like a misconfigured PAT.
func (p RepoProbe) Blocked() bool {
	switch p.Access {
	case AccessDenied, AccessMissing, AccessRejected, AccessReadOnly:
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
// secrets, classifying the answer and attaching the fix. env narrows the
// question to one deployment environment, or "" asks it of the repository.
//
// It probes the destination's public key: the cheapest read that needs a grant
// on the repo at all. Nothing secret is sent and nothing secret comes back — a
// sealing key is public by definition, and it is discarded here anyway. See
// AccessOK for what a pass does and does not prove.
//
// Probing the environment's key rather than the repository's is what makes an
// environment target's preflight worth running: the environment has to exist
// and be reachable for the push to work, and the repository key says nothing
// about either.
func (c *GHClient) CheckRepoAccess(ctx context.Context, repo, env string) RepoProbe {
	_, _, err := c.RepoPublicKey(ctx, repo, env)
	if err != nil {
		return RepoProbe{Access: classifyAccess(err), Err: err, Hint: AccessHint(repo, env, err)}
	}
	// The read passed, so the destination exists and is reachable. Whether a
	// push may actually land there is a separate grant, and asking is the whole
	// point of a preflight — reporting the read alone is what let a rollout
	// reach the PUT before finding out.
	write, _, werr := c.CanWriteSecret(ctx, repo, env)
	switch write {
	case WriteOK:
		// werr is non-nil only in the case where the probe name unexpectedly
		// existed and was deleted. The credential can write, so this is not a
		// blocking outcome, but it must not be swallowed.
		return RepoProbe{Access: AccessOK, Write: WriteOK, Err: werr}
	case WriteDenied:
		return RepoProbe{Access: AccessReadOnly, Write: WriteDenied, Err: werr, Hint: writeHint(repo, env)}
	default:
		// Unsettled: report the destination as readable and say the write was
		// not established, rather than claiming either answer.
		return RepoProbe{Access: AccessOK, Write: WriteUnknown, Err: werr, Hint: AccessHint(repo, env, werr)}
	}
}

// writeHint is the fix for a credential that can read a destination but not
// write it. It is a different sentence from AccessDenied's: the repository is
// already in the grant list — that is how the read succeeded — so telling the
// operator to add it sends them to a setting that is already correct.
func writeHint(repo, env string) string {
	if env != "" {
		return fmt.Sprintf("the GitHub credential can read %s · %s but not write to it — environment secrets need Environments: read *and write* on the fine-grained PAT, not read alone; Secrets: read and write on the repository is necessary too but not sufficient here", repo, env)
	}
	return fmt.Sprintf("the GitHub credential can read %s's Actions secrets but not write them — the fine-grained PAT grants Secrets: read on this repository and needs read *and write*", repo)
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
func AccessHint(repo, env string, err error) string {
	switch classifyAccess(err) {
	case AccessDenied:
		if env != "" {
			return fmt.Sprintf("the GitHub credential cannot reach environment secrets on %s · %s — the repository must be in the fine-grained PAT's repository list with Secrets: read and write, and environment secrets additionally need Environments: read *and write*; an org SAML/IP policy answers the same 403", repo, env)
		}
		return fmt.Sprintf("the GitHub credential cannot reach Actions Secrets on %s — usually the repository is missing from the fine-grained PAT's repository list (Secrets: read and write); an archived repo, disabled Actions, or an org SAML/IP policy answers the same 403", repo)
	case AccessMissing:
		// An environment probe has two ways to 404 and they have different
		// fixes, so the hint names both rather than sending the reader to check
		// a repository that is very likely fine. The environment is the newer
		// and likelier of the two: it is created in the repository's settings,
		// not by pushing to it, so a target can be attached to one that does not
		// exist yet.
		if env != "" {
			return fmt.Sprintf("%s · %s could not be found — either the environment %q does not exist in the repository (create it in Settings → Environments; pushing a secret does not create it), or the repository is missing from the fine-grained PAT's list", repo, env, env)
		}
		return fmt.Sprintf("%s does not exist, or the GitHub credential cannot see it — check the owner/name, and that the repository is in the fine-grained PAT's repository list", repo)
	case AccessRejected:
		// Deliberately says nothing about repo: a refused credential is not a
		// fact about the repository that happened to be asked for, and framing
		// it as one sends the reader to check a grant that is beside the point.
		return "GitHub rejected the credential — the PAT is revoked, expired, or malformed; issue a new one and store it in the vault"
	case AccessUnknown:
		if errors.Is(err, ErrRateLimited) {
			where := repo
			if env != "" {
				where = repo + " · " + env
			}
			return fmt.Sprintf("GitHub is rate-limiting this credential, so %s could not be checked — retry shortly; this says nothing about the repository's grant", where)
		}
	}
	return ""
}
