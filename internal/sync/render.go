package sync

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Einlanzerous/signet/internal/envfile"
	"github.com/Einlanzerous/signet/internal/store"
	"github.com/Einlanzerous/signet/internal/vault"
)

// RenderPushOptions modifies one render push.
type RenderPushOptions struct {
	// AllowShrink permits a push that delivers fewer keys than the last one.
	// Off by default: see ShrinkError for what is being allowed.
	AllowShrink bool
}

// MissingKeysError reports keys a render target manages that the vault cannot
// currently supply. It is a refusal, not a partial render.
//
// Nothing about the destination makes a partial value obviously wrong — a
// shorter env file is still a valid env file — which is exactly the danger. The
// consumer interpolates an absent key to the empty string and deploys a
// half-configured container, and the three incidents behind this target kind
// were all that shape. So the whole push is declined rather than delivering
// what happens to resolve.
type MissingKeysError struct {
	Project string
	Keys    []string
}

func (e *MissingKeysError) Error() string {
	return fmt.Sprintf("%d key(s) the target manages have no value in project %s: %s — set them, or drop them from the target",
		len(e.Keys), e.Project, strings.Join(e.Keys, ", "))
}

// EmptyRenderError reports a rendered target that manages no keys.
//
// It is separated from MissingKeysError because the two have different fixes: a
// missing value wants the value set, and this wants keys attached to the
// target. Both are refusals, and this one is the more urgent — the blob it
// would otherwise deliver is a complete, well-formed env file containing
// nothing, which the consumer would apply in full.
type EmptyRenderError struct {
	Project     string
	Destination string
}

func (e *EmptyRenderError) Error() string {
	return fmt.Sprintf("the %s render → %s manages no keys, so it would deliver an empty environment — attach keys with `signet target add-key` before syncing it",
		e.Project, e.Destination)
}

// ShrinkError reports a render that would deliver fewer keys than the last
// push did.
//
// This is the guard that makes signet safe to put in front of a live
// environment. A GitHub secret's value is never readable back, so nothing can
// diff the destination against the vault — the only account of what is deployed
// is signet's record of what it last sent. A key that leaves the vault
// therefore leaves the deployed environment silently, and the consumer reads it
// as empty rather than as absent.
//
// It is a refusal rather than a warning because the failure it prevents is not
// recoverable by noticing later: by the time a deploy fires, the containers are
// already running against the shortened environment.
type ShrinkError struct {
	Dropped []string
}

func (e *ShrinkError) Error() string {
	return fmt.Sprintf("this render drops %d key(s) the last push delivered: %s — they would become empty in the deployed environment; re-add them, or pass --allow-shrink if the removal is deliberate",
		len(e.Dropped), strings.Join(e.Dropped, ", "))
}

// RenderBlob builds the content a gh-render target delivers, from the values
// the caller resolved.
//
// Completeness is enforced here rather than by the caller. Callers resolve a
// project leniently or strictly for their own reasons — status must not die on
// one broken derivation, render must — but a *push* has only one correct
// answer, and leaving the choice open is how a caller that meant to be
// forgiving would have shipped a half-populated environment.
func RenderBlob(cfg store.GHRenderConfig, project string, want map[string]string) (string, error) {
	// A target managing nothing renders to a header and no entries, which is a
	// valid env file describing an environment with no configuration in it.
	// Delivering that is the most destructive thing this code can do and can
	// never be what was meant — a target is created with a seeded key set, and
	// one that has none is half-configured rather than deliberately empty.
	if len(cfg.Keys) == 0 {
		return "", &EmptyRenderError{Project: project, Destination: cfg.Destination()}
	}
	var pairs []envfile.Pair
	var missing []string
	for _, k := range cfg.Keys {
		v, ok := want[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		pairs = append(pairs, envfile.Pair{Key: k, Value: v})
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", &MissingKeysError{Project: project, Keys: missing}
	}
	return envfile.RenderBlob(pairs), nil
}

// DroppedKeys returns the keys a previous push delivered that this one would
// not. Both sides are treated as sets; order is irrelevant and duplicates
// cannot occur, since every key set signet stores is merged and sorted.
func DroppedKeys(previous, next []string) []string {
	have := make(map[string]bool, len(next))
	for _, k := range next {
		have[k] = true
	}
	var dropped []string
	for _, k := range previous {
		if !have[k] {
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	return dropped
}

// PushRender renders a project's managed keys into one env-file blob and
// delivers it as the value of a single GitHub secret.
//
// want carries the caller's resolved values for the project; every key the
// target manages must appear in it or the push is declined — see RenderBlob.
//
// Its drift record is the digest of the blob rather than any version id: the
// value is composed from many secrets, so no single one of them can speak for
// whether the destination is current. That is the same mechanism a derived
// secret's target already uses, for the same reason.
func PushRender(ctx context.Context, st *store.Store, key []byte, gh *GHClient, t *store.Target,
	want map[string]string, opts RenderPushOptions, actor string, role store.ActorRole) (PushResult, error) {

	cfg, err := t.GHRenderConfig()
	if err != nil {
		return PushResult{}, err
	}
	res := PushResult{TargetID: t.ID, Repo: cfg.Repo, Environment: cfg.Environment, Secret: cfg.SecretName, Dest: cfg.Destination()}

	content, err := RenderBlob(cfg, t.Project, want)
	if err != nil {
		return refuse(st, res, t, cfg, actor, role, err), nil
	}

	// The shrink check runs before anything is sealed or sent. A push refused
	// here has to have changed nothing at the destination, or the guard would
	// be reporting on a state it had already helped create.
	previous, err := t.PushedKeys()
	if err != nil {
		return PushResult{}, err
	}
	if previous != nil && !opts.AllowShrink {
		if dropped := DroppedKeys(previous, cfg.Keys); len(dropped) > 0 {
			return refuse(st, res, t, cfg, actor, role, &ShrinkError{Dropped: dropped}), nil
		}
	}

	digest := vault.ValueDigest(key, content)
	prov := store.PushProvenance{Digest: digest, Keys: cfg.Keys}

	// Out-of-band change detection before the overwrite, as for a single
	// secret: someone running `gh secret set` by hand is precisely the workflow
	// this target kind replaces, so the first sync after one is a
	// reconciliation and the ledger should say so.
	kind := store.KindSyncPush
	if drift, derr := gh.CheckGHDrift(ctx, cfg.Repo, cfg.Environment, cfg.SecretName, t.LastPushedAt); derr == nil && drift == GHOutOfBand && t.LastPushedAt != "" {
		res.Note = "destination changed out-of-band since last push — re-sealing"
		kind = store.KindDriftReconcile
	}

	stat, err := pushOne(ctx, gh, cfg.GHConfig, []byte(content))
	status := &store.AuditStatus{}
	if stat.HTTPStatus != 0 {
		status.HTTPStatus = store.Measured(stat.HTTPStatus)
	}
	if stat.Measured {
		status.LatencyMS = store.Measured(stat.LatencyMS)
	}
	if err != nil {
		res.State = "error"
		res.Err = err.Error()
		res.Hint = AccessHint(cfg.Repo, cfg.Environment, err)
		status.Outcome = store.OutcomeFailed
		recordPush(st, &res, store.AuditRecord{
			Actor: actor, Action: "sync.push.failed", TargetID: t.ID,
			Details:   fmt.Sprintf("%s render (%d keys) → %s: %s", t.Project, len(cfg.Keys), cfg.Destination(), err),
			EventKind: kind, ActorRole: role, Status: status,
		}, "error", err.Error(), nil, "")
		return res, nil
	}

	res.State = "in sync"
	status.Outcome = store.OutcomeDelivered
	// The key count and digest are what makes this entry auditable after the
	// fact: the value is unreadable at both ends — encrypted here, write-only
	// there — so the ledger's account of what was delivered is the only one.
	detail := fmt.Sprintf("sealed & pushed %s render → %s · %s · %d keys · #%s",
		t.Project, cfg.Destination(), cfg.Scope(), len(cfg.Keys), digest)
	if grown := DroppedKeys(cfg.Keys, previous); previous != nil && len(grown) > 0 {
		detail += fmt.Sprintf(" (+%d: %s)", len(grown), strings.Join(grown, ", "))
	}
	if res.Note != "" {
		detail += " (" + res.Note + ")"
	}
	recordPush(st, &res, store.AuditRecord{
		Actor: actor, Action: "sync.push", TargetID: t.ID,
		Details: detail, EventKind: kind, ActorRole: role, Status: status,
	}, "in sync", "", &prov, nowRFC3339())
	// The entry above is the record of the push. It carries no SecretID — a
	// blob composed from many secrets has no single one to name — which left
	// every key in it invisible to `audit --secret`, the query asked from the
	// credential's side. See internal/sync/audit.go (SGNT-34).
	auditRenderedKeys(st, &res, t, cfg, kind, actor, role, digest)
	return res, nil
}

// refuse records a push signet declined to attempt, and shapes it as a failed
// PushResult so a caller reports and exits on it exactly as it would a rejected
// one.
//
// It goes in the ledger despite nothing having been sent. A refusal is a
// decision signet made about a live destination, and the ledger is the record
// of those — an operator asking why the environment is a week stale should find
// the answer there rather than in a terminal scrollback that is gone.
func refuse(st *store.Store, res PushResult, t *store.Target, cfg store.GHRenderConfig,
	actor string, role store.ActorRole, cause error) PushResult {

	res.State = "error"
	res.Err = cause.Error()
	// The error text is already the fix, so a hint alongside it would only
	// repeat itself; see PushResult.Hint, which exists for failures whose own
	// message leads nowhere.
	recordPush(st, &res, store.AuditRecord{
		Actor: actor, Action: "sync.push.refused", TargetID: t.ID,
		Details:   fmt.Sprintf("%s render → %s declined: %s", t.Project, cfg.Destination(), cause),
		EventKind: store.KindSyncPush, ActorRole: role,
		Status: &store.AuditStatus{Outcome: store.OutcomeFailed},
	}, store.TargetRefused, cause.Error(), nil, "")
	return res
}
