package store

import (
	"strings"
	"testing"
)

func mustAddRenderTarget(t *testing.T, s *Store, project, repo, env, secretName string, keys []string) *Target {
	t.Helper()
	var tgt *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, err := m.AddGHRenderTarget(project, repo, env, secretName, keys)
		if err != nil {
			return AuditRecord{}, err
		}
		tgt = added
		return testRecord("render target " + repo), nil
	}); err != nil {
		t.Fatal(err)
	}
	return tgt
}

// The environment belongs in the destination's identity. The same secret name
// in the same repository is one destination at repository scope and a different
// one under an environment — treating the pair as unique would refuse the
// second as a duplicate of the first.
func TestEnvironmentDistinguishesOtherwiseIdenticalDestinations(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "csrv", "TOKEN", "", false)

	repoScoped := mustAddGHTarget(t, s, sec.ID, "owner/repo", "TOKEN")
	var envScoped *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		added, err := m.AddGHTarget(sec.ID, "owner/repo", "home-server", "TOKEN")
		if err != nil {
			return AuditRecord{}, err
		}
		envScoped = added
		return testRecord("env target"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if repoScoped.ID == envScoped.ID {
		t.Fatal("the environment-scoped target reused the repository-scoped one")
	}

	found, err := s.FindGHTarget(sec.ID, "owner/repo", "home-server", "TOKEN")
	if err != nil || found == nil || found.ID != envScoped.ID {
		t.Fatalf("lookup by environment found %v (err %v)", found, err)
	}
	found, err = s.FindGHTarget(sec.ID, "owner/repo", "", "TOKEN")
	if err != nil || found == nil || found.ID != repoScoped.ID {
		t.Fatalf("lookup at repository scope found %v (err %v)", found, err)
	}
	// A scope nobody attached must not match either of them.
	miss, err := s.FindGHTarget(sec.ID, "owner/repo", "staging", "TOKEN")
	if err != nil || miss != nil {
		t.Fatalf("lookup in an unattached environment found %v (err %v)", miss, err)
	}
}

func TestRenderTargetRoundTripsItsConfig(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"BETA", "ALPHA", "ALPHA"})

	cfg, err := tgt.GHRenderConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Keys are stored merged and sorted, as a file target's are, so the blob
	// they render is a function of the set rather than of insertion order.
	if strings.Join(cfg.Keys, ",") != "ALPHA,BETA" {
		t.Fatalf("keys = %v", cfg.Keys)
	}
	if cfg.Environment != "home-server" || cfg.SecretName != "PROD_ENV_FILE" || cfg.Repo != "o/r" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if got := cfg.Destination(); got != "o/r · home-server · PROD_ENV_FILE" {
		t.Fatalf("destination = %q", got)
	}
	if got := (GHConfig{Repo: "o/r", SecretName: "X"}).Destination(); got != "o/r · X" {
		t.Fatalf("repository-scoped destination = %q", got)
	}

	// It is project-scoped, so it is reachable the way file targets are and not
	// through any secret's target list.
	byProject, err := s.RenderTargetsForProject("csrv")
	if err != nil || len(byProject) != 1 || byProject[0].ID != tgt.ID {
		t.Fatalf("RenderTargetsForProject = %v (err %v)", byProject, err)
	}
	all, err := s.RenderTargets()
	if err != nil || len(all) != 1 {
		t.Fatalf("RenderTargets = %v (err %v)", all, err)
	}
}

func TestAddRenderKeysMergesAndReportsUnchanged(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA"})

	var outcome Outcome
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		updated, o, err := m.AddRenderKeys(tgt, []string{"BETA"})
		if err != nil {
			return AuditRecord{}, err
		}
		tgt, outcome = updated, o
		return testRecord("add key"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeUpdated {
		t.Fatalf("outcome = %q", outcome)
	}
	cfg, _ := tgt.GHRenderConfig()
	if strings.Join(cfg.Keys, ",") != "ALPHA,BETA" {
		t.Fatalf("keys = %v", cfg.Keys)
	}

	// Re-adding a key already managed is not an update. Reporting it as one
	// would tell the operator to go sync a change that does not exist.
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		_, o, err := m.AddRenderKeys(tgt, []string{"BETA"})
		if err != nil {
			return AuditRecord{}, err
		}
		outcome = o
		return testRecord("add key again"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeUnchanged {
		t.Fatalf("re-adding a managed key reported %q", outcome)
	}
}

// The key set a push delivered is state, not config: a failed push must leave
// the last successful delivery's record intact, or the shrink check compares
// against a baseline that never reached the destination.
func TestPushedKeySetSurvivesAFailedPush(t *testing.T) {
	s := testStore(t)
	tgt := mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA", "BETA"})

	if err := s.UpdateTargetPush(tgt.ID, "in sync", "", &PushProvenance{Digest: "d1", Keys: []string{"ALPHA", "BETA"}}, "2026-08-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTargetPush(tgt.ID, "error", "boom", nil, ""); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.RenderTargetsForProject("csrv")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := reloaded[0].PushedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "ALPHA,BETA" {
		t.Fatalf("failed push clobbered the delivered key set: %v", keys)
	}
	if reloaded[0].LastPushedDigest != "d1" || reloaded[0].LastPushedAt != "2026-08-12T00:00:00Z" {
		t.Fatalf("failed push clobbered the delivery record: %+v", reloaded[0])
	}

	// A target that has never pushed has no baseline, which must read as "no
	// record" rather than as "delivered nothing".
	fresh := mustAddRenderTarget(t, s, "other", "o/r", "", "OTHER_FILE", []string{"X"})
	if keys, err := fresh.PushedKeys(); err != nil || keys != nil {
		t.Fatalf("a never-pushed target reported keys %v (err %v)", keys, err)
	}
}

// Migration 005 rebuilds the targets table. Rows written under the old schema
// have to come through it unchanged — the vault's whole delivery history hangs
// off them.
func TestMigrationPreservesExistingTargets(t *testing.T) {
	s := testStore(t)
	sec := mustCreateSecret(t, s, "csrv", "TOKEN", "", false)
	gh := mustAddGHTarget(t, s, sec.ID, "owner/repo", "TOKEN")
	file, _ := mustUpsertFileTarget(t, s, "csrv", "/tmp/x/.env", []string{"TOKEN"}, "0600")
	if err := s.UpdateTargetPush(gh.ID, "in sync", "", &PushProvenance{VersionID: "v1", Digest: "dd"}, "2026-08-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	targets, err := s.ListTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d", len(targets))
	}
	byID := map[string]Target{}
	for _, tg := range targets {
		byID[tg.ID] = tg
	}
	kept := byID[gh.ID]
	if kept.Kind != "gh-actions" || kept.SecretID != sec.ID ||
		kept.LastPushedVersionID != "v1" || kept.LastPushedDigest != "dd" ||
		kept.LastPushedAt != "2026-08-01T00:00:00Z" || kept.LastState != "in sync" {
		t.Fatalf("gh target came through the rebuild altered: %+v", kept)
	}
	if byID[file.ID].Kind != "file" || byID[file.ID].Project != "csrv" {
		t.Fatalf("file target came through the rebuild altered: %+v", byID[file.ID])
	}
	// The indexes the rebuild recreates are what these lookups use.
	if got, err := s.TargetsForSecret(sec.ID); err != nil || len(got) != 1 {
		t.Fatalf("TargetsForSecret = %v (err %v)", got, err)
	}
	if got, err := s.FileTargetsForProject("csrv"); err != nil || len(got) != 1 {
		t.Fatalf("FileTargetsForProject = %v (err %v)", got, err)
	}
}

// A refusal is a local decision that touches nothing at the destination, so it
// must not stand in front of the fact an operator actually needs: that the
// environment is holding values the vault has moved on from. Reporting "error"
// for both left one refused render hiding drift until some later sync happened
// to succeed.
func TestARefusedPushDoesNotHideDrift(t *testing.T) {
	refused := Target{
		LastState: TargetRefused, LastError: "would drop BETA",
		LastPushedAt: "2026-08-01T00:00:00Z", LastPushedDigest: "aaaaaaaaaaaa",
	}
	if got := refused.GHState(nil, "bbbbbbbbbbbb"); got != "drift" {
		t.Fatalf("a refused target reports %q, hiding the drift underneath it", got)
	}
	if got := refused.GHState(nil, "aaaaaaaaaaaa"); got != "in sync" {
		t.Fatalf("a refused target whose blob is unchanged reports %q", got)
	}

	// A delivery that was attempted and failed is a different fact, and still
	// reports as one.
	failed := Target{
		LastState: "error", LastError: "403 from GitHub",
		LastPushedAt: "2026-08-01T00:00:00Z", LastPushedDigest: "aaaaaaaaaaaa",
	}
	if got := failed.GHState(nil, "bbbbbbbbbbbb"); got != "error" {
		t.Fatalf("a failed push reports %q rather than error", got)
	}
}

// One GitHub secret holds one value. Two targets pointing at it overwrite each
// other on every sync, and each reports "in sync" against its own record — so
// the deployed value becomes a function of iteration order.
func TestOneDestinationCannotBeClaimedByTwoTargets(t *testing.T) {
	s := testStore(t)
	mustAddRenderTarget(t, s, "csrv", "o/r", "home-server", "PROD_ENV_FILE", []string{"ALPHA"})

	var found *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		var err error
		found, err = m.FindGHDestination("o/r", "home-server", "PROD_ENV_FILE")
		if err != nil {
			return AuditRecord{}, err
		}
		return AuditRecord{
			Actor: "test", Action: "noop", Details: "probe",
			EventKind: KindTargetConfig, ActorRole: RoleHuman,
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("the destination reads as unclaimed while a gh-render target delivers to it")
	}
	if found.Kind != "gh-render" {
		t.Fatalf("claimed by a %s target", found.Kind)
	}

	// The environment is part of the identity: the same name in another
	// environment is a different live secret and stays free.
	var other *Target
	if _, err := s.Mutate(func(m *Mutation) (AuditRecord, error) {
		var err error
		other, err = m.FindGHDestination("o/r", "staging", "PROD_ENV_FILE")
		if err != nil {
			return AuditRecord{}, err
		}
		return AuditRecord{
			Actor: "test", Action: "noop", Details: "probe",
			EventKind: KindTargetConfig, ActorRole: RoleHuman,
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if other != nil {
		t.Fatalf("a different environment reads as claimed: %+v", other)
	}
}
