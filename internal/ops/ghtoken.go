package ops

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Einlanzerous/signet/internal/disclose"
	"github.com/Einlanzerous/signet/internal/resolve"
	"github.com/Einlanzerous/signet/internal/store"
)

// The vault's own GitHub credential. sync reads it when the environment
// carries no token, so the PAT can be held the way every other secret is —
// encrypted, expiry tracked, reads audited — instead of being arranged by each
// caller's shell on the way in.
const (
	GHTokenProject = "signet"
	GHTokenName    = "SIGNET_PAT"
)

// ghTokenFix is the command that stores a PAT under the ref sync looks for,
// quoted by every failure below so the fix is in hand rather than looked up.
// Each of these is read at the moment a sync stopped working, which is not when
// anyone wants to go and reconstruct the invocation.
const ghTokenFix = "`signet set --project " + GHTokenProject + " --name " + GHTokenName +
	" --expires YYYY-MM-DD`, with the PAT on stdin"

// GHTokenEnvNone names the environment half of the lookup chain, in full,
// wherever signet reports that it found nothing there.
//
// Config collapses SIGNET_GITHUB_TOKEN and SIGNET_PAT into one value before it
// reaches this package, so by the time a resolve fails there is no way to know
// which of the two was consulted — which is exactly why both have to be named.
// A message that mentions only SIGNET_GITHUB_TOKEN misdirects the one person
// most likely to read it: whoever exported SIGNET_PAT with a typo or an empty
// value, and is now being told to go and look at a variable they never used.
//
// "No credential in", not "unset": a variable holding only whitespace is also
// no credential, and telling someone who exported one that it is unset would
// be the same misdirection in a narrower form.
const GHTokenEnvNone = "no credential in SIGNET_GITHUB_TOKEN or SIGNET_PAT"

// ActionSecretRead is the ledger verb for signet reading a secret in order to
// use it itself, as distinct from `secret.reveal`, which is plaintext handed to
// a person. Both are KindSecretReveal — a decrypt is a decrypt, and neither
// should be filterable out of a review of who touched a credential — but the
// verb keeps "the operator saw this value" apart from "sync authenticated with
// it", which is the distinction an audit of the root credential turns on.
const ActionSecretRead = "secret.read"

// TokenSource records where a resolved token came from. A vault fallback
// decrypts the credential that can rewrite every other destination, so the
// caller is expected to say out loud that it happened.
type TokenSource string

const (
	// TokenFromEnv is a token the environment supplied.
	TokenFromEnv TokenSource = "env"
	// TokenFromVault is signet/SIGNET_PAT, read out of the vault.
	TokenFromVault TokenSource = "vault"
)

// TokenPurpose is what a resolved credential is about to be used for, written
// into the ledger entry the vault fallback appends. The root PAT is read for
// more than one reason now — a push, and the preflight that checks a repo is
// even reachable — and an audit of that credential is worth less if every read
// claims to have been a sync.
type TokenPurpose string

const (
	// PurposeSync is authenticating a push to GitHub Actions.
	PurposeSync TokenPurpose = "authenticate GitHub Actions sync"
	// PurposePreflight is checking whether the PAT can reach a repository's
	// Actions secrets at all. No secret material leaves the vault for it.
	PurposePreflight TokenPurpose = "preflight a repository's Actions Secrets access"
)

// GHToken is a resolved GitHub credential and where it came from.
type GHToken struct {
	Value  string
	Source TokenSource
	// ExpiresAt is the vault's recorded expiry (RFC3339), empty when the token
	// came from the environment or carries none: signet knows nothing about the
	// lifetime of a token it was simply handed.
	ExpiresAt string
}

// ResolveGHToken returns the credential sync should authenticate with. envToken
// is the environment's answer — SIGNET_GITHUB_TOKEN, or SIGNET_PAT, which
// config collapses into one value — and when it is empty the vault's own
// signet/SIGNET_PAT is read instead.
//
// The fallback decrypts a credential, so it is appended to the ledger like any
// other plaintext leaving the vault, and a ledger write that fails fails the
// resolve: a root credential read that nothing recorded is exactly what this
// vault exists to prevent.
func ResolveGHToken(st *store.Store, key []byte, envToken, actor string, role store.ActorRole) (GHToken, error) {
	return ResolveGHTokenFor(st, key, envToken, actor, role, PurposeSync)
}

// ResolveGHTokenFor is ResolveGHToken with the ledger entry's stated purpose
// named by the caller, for reads that are not a push.
func ResolveGHTokenFor(st *store.Store, key []byte, envToken, actor string, role store.ActorRole, purpose TokenPurpose) (GHToken, error) {
	// Trimmed before it is judged present, and for the reason the vault's own
	// value is trimmed below: this goes straight into an Authorization header.
	// An env var holding only whitespace — a CRLF-terminated line exported from
	// a .env file, a quoted trailing space — is not a credential, and treating
	// it as one would skip the vault fallback and hand GitHub a header it
	// answers with a 401 that names neither the variable nor the whitespace.
	if envToken = strings.TrimSpace(envToken); envToken != "" {
		return GHToken{Value: envToken, Source: TokenFromEnv}, nil
	}
	ref := GHTokenProject + "/" + GHTokenName
	sec, err := st.GetSecret(GHTokenProject, GHTokenName)
	if err != nil {
		return GHToken{}, err
	}
	if sec == nil {
		return GHToken{}, fmt.Errorf("%s, and the vault has no %s — cannot push to GitHub Actions; store the PAT with %s",
			GHTokenEnvNone, ref, ghTokenFix)
	}
	// Checked before the decrypt, and reported as itself: an expired PAT
	// otherwise surfaces as a 401 from the GitHub API, which names neither the
	// credential that failed nor the reason it did.
	if expired, on := expiredOn(sec.ExpiresAt); expired {
		return GHToken{}, fmt.Errorf("%s expired on %s — cannot push to GitHub Actions; issue a new PAT, then %s",
			ref, on, ghTokenFix)
	}
	// Through resolve like every other reader, so a derived PAT resolves
	// instead of reporting no value and recommending `signet set` — which
	// refuses derived secrets, leaving an instruction that cannot be followed.
	r, err := resolve.Current(st, key, sec)
	switch {
	// A registered secret with nothing in it is a half-finished `set`, not a
	// broken vault, so it gets the same one-command fix as an absent one rather
	// than a bare statement of the fact.
	case errors.Is(err, resolve.ErrNoVersion):
		return GHToken{}, fmt.Errorf("%s, and %s has no value stored — cannot push to GitHub Actions; store the PAT with %s",
			GHTokenEnvNone, ref, ghTokenFix)
	// A derivation that will not expand names its own cause — a missing input,
	// a cycle — and that is more use here than a generic failure to read.
	case err != nil:
		return GHToken{}, fmt.Errorf("%s cannot be resolved — cannot push to GitHub Actions: %w", ref, err)
	}
	plain := r.Value
	// Trimmed at the point of use. The value goes straight into an Authorization
	// header, and a trailing newline from `printf | signet set` or a \r carried
	// in from a CRLF env file is refused by the transport with an error that
	// names neither the credential nor the whitespace that broke it.
	token := strings.TrimSpace(plain)
	if token == "" {
		return GHToken{}, fmt.Errorf("%s is empty — cannot push to GitHub Actions; store the PAT with %s", ref, ghTokenFix)
	}
	rec := store.AuditRecord{
		Actor: actor, Action: ActionSecretRead, SecretID: sec.ID,
		Details: fmt.Sprintf("read %s %s to %s (%s)",
			ref, provenanceOf(r), purpose, GHTokenEnvNone),
		EventKind: store.KindSecretReveal, ActorRole: role,
		Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
	}
	if _, err := st.AppendAudit(rec); err != nil {
		return GHToken{}, fmt.Errorf("%s read but not recorded: %w", ref, err)
	}
	// The fifth disclosure channel, found by the review on #43 (SGNT-34).
	//
	// The resolve.Current above exists precisely so a DERIVED PAT works, and a
	// derived PAT's plaintext is its inputs' — decrypted here and put into an
	// Authorization header. Recording only against the PAT left
	// `signet audit --secret <input>` empty for a read that sent that
	// credential off-box, on the one secret in the vault that can rewrite every
	// other destination.
	//
	// Same rule, same traversal, as reveal, exec, render and the pushes; see
	// internal/disclose for why it is not restated here.
	if err := disclose.Inputs(st, sec, store.AuditRecord{
		Actor: actor, Action: ActionSecretRead,
		Details: fmt.Sprintf("value read to %s via %s, which derives from it (%s)",
			purpose, ref, GHTokenEnvNone),
		EventKind: store.KindSecretReveal, ActorRole: role,
		Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
	}); err != nil {
		return GHToken{}, fmt.Errorf("%s read but its derivation inputs were not recorded: %w", ref, err)
	}
	return GHToken{Value: token, Source: TokenFromVault, ExpiresAt: sec.ExpiresAt}, nil
}

// expiredOn reports whether an RFC3339 expiry has passed, and the date it was.
//
// An expiry is a date: both `set --expires` and the API store midnight UTC of
// the day given, and GitHub honors a PAT through the whole of that day. So the
// credential is spent only once the day is over — refusing at 00:00:00Z would
// reject, for its entire last day, a token GitHub still accepts.
//
// An unparseable or absent expiry is not an expiry: signet declines to guess a
// lifetime for a credential whose recorded one it cannot read.
func expiredOn(expiresAt string) (bool, string) {
	if expiresAt == "" {
		return false, ""
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return false, ""
	}
	if time.Now().Before(t.AddDate(0, 0, 1)) {
		return false, ""
	}
	return true, t.Format("2006-01-02")
}

// provenanceOf names what the ledger should cite for a value that was read: the
// version a stored secret came from, or the fingerprint of a derived one, which
// has no version to name.
func provenanceOf(r resolve.Resolved) string {
	if r.Version != nil {
		return fmt.Sprintf("version %d #%s", r.Version.VersionNo, r.Version.VHash)
	}
	return "derived #" + r.Digest
}
