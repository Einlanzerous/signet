package ops

import (
	"fmt"
	"time"

	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// The vault's own GitHub credential. sync reads it when the environment
// carries no token, so the PAT can be held the way every other secret is —
// encrypted, expiry tracked, reads audited — instead of being arranged by each
// caller's shell on the way in.
const (
	GHTokenProject = "signet"
	GHTokenName    = "SIGNET_PAT"
)

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
	if envToken != "" {
		return GHToken{Value: envToken, Source: TokenFromEnv}, nil
	}
	ref := GHTokenProject + "/" + GHTokenName
	sec, err := st.GetSecret(GHTokenProject, GHTokenName)
	if err != nil {
		return GHToken{}, err
	}
	if sec == nil {
		return GHToken{}, fmt.Errorf("SIGNET_GITHUB_TOKEN is not set and the vault has no %s — cannot push to GitHub Actions; store the PAT with `signet set --project %s --name %s --expires YYYY-MM-DD`",
			ref, GHTokenProject, GHTokenName)
	}
	// Checked before the decrypt, and reported as itself: an expired PAT
	// otherwise surfaces as a 401 from the GitHub API, which names neither the
	// credential that failed nor the reason it did.
	if expired, on := expiredOn(sec.ExpiresAt); expired {
		return GHToken{}, fmt.Errorf("%s expired on %s — cannot push to GitHub Actions; issue a new PAT, then `signet set --project %s --name %s --expires YYYY-MM-DD`",
			ref, on, GHTokenProject, GHTokenName)
	}
	cur, err := st.CurrentVersion(sec.ID)
	if err != nil {
		return GHToken{}, err
	}
	if cur == nil {
		return GHToken{}, fmt.Errorf("SIGNET_GITHUB_TOKEN is not set and %s has no versions — cannot push to GitHub Actions", ref)
	}
	plain, err := vault.Decrypt(key, cur.Nonce, cur.Ciphertext)
	if err != nil {
		return GHToken{}, fmt.Errorf("%s: %w", ref, err)
	}
	if len(plain) == 0 {
		return GHToken{}, fmt.Errorf("%s is empty — cannot push to GitHub Actions", ref)
	}
	if _, err := st.AppendAudit(store.AuditRecord{
		Actor: actor, Action: "secret.read", SecretID: sec.ID,
		Details: fmt.Sprintf("read %s version %d #%s to authenticate GitHub Actions sync (SIGNET_GITHUB_TOKEN unset)",
			ref, cur.VersionNo, cur.VHash),
		EventKind: store.KindSecretReveal, ActorRole: role,
		Status: &store.AuditStatus{Outcome: store.OutcomeDelivered},
	}); err != nil {
		return GHToken{}, fmt.Errorf("%s read but not recorded: %w", ref, err)
	}
	return GHToken{Value: string(plain), Source: TokenFromVault, ExpiresAt: sec.ExpiresAt}, nil
}

// expiredOn reports whether an RFC3339 expiry has passed, and the date it was.
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
	if time.Now().Before(t) {
		return false, ""
	}
	return true, t.Format("2006-01-02")
}
