// Package sync reconciles vault secrets with their outbound targets.
//
// GitHub Actions repo secrets are push-only: workflows resolve ${{ secrets.* }}
// from GitHub's own store, so a local vault can never serve them at runtime —
// sealing with the repo public key and PUTting is the only mechanism. Drift
// detection is therefore metadata-based (GitHub never returns secret values):
// an out-of-band update or a missing secret counts as drift.
package sync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Sentinels for the GitHub API failures signet can attribute to a cause. They
// exist so a caller can tell "this credential was never granted the repo" apart
// from "GitHub is unhappy for some other reason" without matching on the
// response body, which is prose GitHub is free to reword.
var (
	// ErrNotFound reports a 404 from the GitHub API (repo or secret absent).
	ErrNotFound = errors.New("not found")
	// ErrUnauthorized reports a 401: the credential itself was rejected.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden reports a 403 that is about what the credential may reach
	// rather than how often it asks. With a fine-grained PAT this is nearly
	// always a repository missing from the token's grant list.
	ErrForbidden = errors.New("forbidden")
	// ErrRateLimited reports a throttled request, which is a 403 as often as it
	// is a 429 and must not be read as a missing grant.
	ErrRateLimited = errors.New("rate limited")
)

// apiError is a non-2xx GitHub response: the full transport detail, which is
// what the ledger records, wrapped around the sentinel that classifies it.
// Error() is unchanged from the bare message so nothing loses the status line
// or the body, and errors.Is still reaches the cause.
type apiError struct {
	kind error // sentinel, nil when the status maps to no particular cause
	msg  string
}

func (e *apiError) Error() string { return e.msg }
func (e *apiError) Unwrap() error { return e.kind }

// flatten collapses a response body onto one line. GitHub pretty-prints its
// error JSON, and this string becomes both a terminal line under a failed push
// and the Details column of a ledger row — neither of which survives an
// embedded newline intact. Every token is kept; only the spacing between them
// is normalized.
func flatten(body string) string { return strings.Join(strings.Fields(body), " ") }

// classifyStatus maps a failing response to its cause, or nil when the status
// says nothing specific.
//
// A throttled request has to be separated from a denied one, because GitHub
// answers both with 403 and the same "Forbidden" status line: reading the code
// alone would send an operator off to edit a PAT that is in fact correct.
//
// Headers settle it when they can. They often cannot — a *secondary* rate limit
// comes back 403 with a non-zero remaining count and frequently no Retry-After,
// and the only thing distinguishing it is the message. So the body is consulted
// as a fallback, narrowly: it can only ever downgrade a denial to "inconclusive
// and worth retrying", never the other way, so GitHub rewording it costs the
// hint's precision rather than its correctness.
func classifyStatus(resp *http.Response, body string) error {
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusForbidden:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" {
			return ErrRateLimited
		}
		if lower := strings.ToLower(body); strings.Contains(lower, "rate limit") || strings.Contains(lower, "abuse") {
			return ErrRateLimited
		}
		return ErrForbidden
	}
	return nil
}

// GHClient is a minimal GitHub REST client for Actions repo secrets.
type GHClient struct {
	BaseURL string // default https://api.github.com
	Token   string
	HTTP    *http.Client
}

// NewGHClient builds a client with defaults.
func NewGHClient(token string) *GHClient {
	return &GHClient{BaseURL: "https://api.github.com", Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// PublicKey is a repository's Actions secret sealing key.
type PublicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"` // base64-encoded 32-byte curve25519 public key
}

// SecretMeta is the metadata GitHub exposes for an Actions secret. Values are
// never readable back.
type SecretMeta struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// CallStat reports the transport-level outcome of one GitHub API call, so the
// audit ledger can record what actually happened on the wire (a real status
// code and elapsed time) rather than an assumed one.
//
// HTTPStatus is 0 when the request never produced a response. Measured says
// whether a request was issued and timed at all, which LatencyMS alone cannot:
// a call that completed in under a millisecond and a call that never happened
// both leave LatencyMS at 0.
type CallStat struct {
	HTTPStatus int
	LatencyMS  int64
	Measured   bool
}

func (c *GHClient) do(ctx context.Context, method, path string, body []byte, out any) (CallStat, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return CallStat{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	started := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return CallStat{LatencyMS: time.Since(started).Milliseconds(), Measured: true}, err
	}
	defer resp.Body.Close()
	stat := CallStat{HTTPStatus: resp.StatusCode, LatencyMS: time.Since(started).Milliseconds(), Measured: true}
	// Every failing status reads its body, 404 included. The ledger entry for a
	// failed push is the only durable record of what GitHub actually said, and a
	// 404 that reports nothing but "not found" leaves an operator with a repo
	// name and no way to tell a typo from a revoked grant.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		body := flatten(string(msg))
		return stat, &apiError{
			kind: classifyStatus(resp, body),
			msg:  strings.TrimSpace(fmt.Sprintf("%s %s: %s: %s", method, path, resp.Status, body)),
		}
	}
	if out != nil {
		return stat, json.NewDecoder(resp.Body).Decode(out)
	}
	return stat, nil
}

// secretsBase is the API path prefix for a destination's secrets: the
// repository's Actions secrets, or an environment's.
//
// The two are not a URL parameter apart — the environment form drops the
// "actions" segment entirely — and each has its own sealing key, so this is the
// one place that decides which surface a call lands on. Everything reached
// through here (public key, PUT, metadata) has to agree on that choice: sealing
// against the repository key and PUTting to the environment path produces a
// secret GitHub accepts and no workflow can decrypt.
//
// env is escaped because environment names are free text — "home server" and
// "staging/eu" are both legal, and neither survives being pasted into a path
// raw. repo and name are not: both are already constrained to path-safe
// characters by GitHub, and escaping the "/" in owner/name would break it.
func secretsBase(repo, env string) string {
	if env == "" {
		return "/repos/" + repo + "/actions/secrets"
	}
	return "/repos/" + repo + "/environments/" + url.PathEscape(env) + "/secrets"
}

// RepoPublicKey fetches the sealing key for owner/name, scoped to env when it
// is non-empty. An environment seals with its own key, not the repository's.
func (c *GHClient) RepoPublicKey(ctx context.Context, repo, env string) (PublicKey, CallStat, error) {
	var pk PublicKey
	stat, err := c.do(ctx, http.MethodGet, secretsBase(repo, env)+"/public-key", nil, &pk)
	return pk, stat, err
}

// PutSecret creates or updates an Actions secret with a sealed value, at
// repository scope or under env.
func (c *GHClient) PutSecret(ctx context.Context, repo, env, name, sealedB64, keyID string) (CallStat, error) {
	body, _ := json.Marshal(map[string]string{"encrypted_value": sealedB64, "key_id": keyID})
	return c.do(ctx, http.MethodPut, secretsBase(repo, env)+"/"+name, body, nil)
}

// GetSecretMeta fetches an Actions secret's metadata (ErrNotFound if absent).
func (c *GHClient) GetSecretMeta(ctx context.Context, repo, env, name string) (SecretMeta, error) {
	var m SecretMeta
	_, err := c.do(ctx, http.MethodGet, secretsBase(repo, env)+"/"+name, nil, &m)
	return m, err
}

// Seal encrypts plaintext to the repo public key with a libsodium-compatible
// anonymous sealed box and returns it base64-encoded.
func Seal(publicKeyB64 string, plaintext []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("seal: bad public key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("seal: public key must be 32 bytes, got %d", len(raw))
	}
	var pk [32]byte
	copy(pk[:], raw)
	sealed, err := box.SealAnonymous(nil, plaintext, &pk, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// GHDrift classifies a gh-actions target's remote state.
type GHDrift string

const (
	// GHInSync means the destination reflects our last push.
	GHInSync GHDrift = "in sync"
	// GHMissing means the destination secret does not exist.
	GHMissing GHDrift = "missing"
	// GHOutOfBand means the destination changed after our last push.
	GHOutOfBand GHDrift = "drift"
)

// CheckGHDrift compares remote metadata against our last recorded push time.
func (c *GHClient) CheckGHDrift(ctx context.Context, repo, env, name, lastPushedAt string) (GHDrift, error) {
	meta, err := c.GetSecretMeta(ctx, repo, env, name)
	if errors.Is(err, ErrNotFound) {
		return GHMissing, nil
	}
	if err != nil {
		return "", err
	}
	if lastPushedAt == "" {
		return GHOutOfBand, nil // exists remotely but we never pushed it
	}
	pushed, err1 := time.Parse(time.RFC3339, lastPushedAt)
	updated, err2 := time.Parse(time.RFC3339, meta.UpdatedAt)
	if err1 != nil || err2 != nil {
		return GHInSync, nil // unparseable timestamps: assume ok rather than false-alarm
	}
	// Small tolerance: GitHub's updated_at is set momentarily after our PUT.
	if updated.After(pushed.Add(2 * time.Minute)) {
		return GHOutOfBand, nil
	}
	return GHInSync, nil
}
