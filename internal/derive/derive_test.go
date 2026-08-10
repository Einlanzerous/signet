package derive

import (
	"strings"
	"testing"
)

// vault is a Lookup over a literal map. Keys are "project/NAME"; a value
// beginning with "=" is a derivation rather than a literal.
type vault map[string]string

func (v vault) look(r Ref) (Entry, error) {
	s, ok := v[r.String()]
	if !ok {
		return Entry{Missing: true}, nil
	}
	if strings.HasPrefix(s, "=") {
		return Entry{Derivation: s[1:]}, nil
	}
	return Entry{Value: s}, nil
}

func TestResolveComposesAcrossProjects(t *testing.T) {
	v := vault{"construct-server/DRYDOCK_DB_PASSWORD": "hunter2"}
	got, err := Resolve(
		Ref{Project: "drydock", Name: "DRYDOCK_DATABASE_URL"},
		"postgres://drydock_user:{{construct-server/DRYDOCK_DB_PASSWORD}}@127.0.0.1:5432/drydock",
		v.look)
	if err != nil {
		t.Fatal(err)
	}
	const want = "postgres://drydock_user:hunter2@127.0.0.1:5432/drydock"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The motivating bug in one assertion: rotating the input changes the derived
// value with nothing else touched. A stored copy could not do this.
func TestRotatingAnInputChangesTheDerivedValue(t *testing.T) {
	v := vault{"construct-server/PW": "old"}
	const tmpl = "postgres://u:{{construct-server/PW}}@h/db"
	origin := Ref{Project: "drydock", Name: "URL"}

	before, err := Resolve(origin, tmpl, v.look)
	if err != nil {
		t.Fatal(err)
	}
	v["construct-server/PW"] = "new"
	after, err := Resolve(origin, tmpl, v.look)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("derived value did not follow its input")
	}
	if !strings.Contains(after, "new") || strings.Contains(after, "old") {
		t.Errorf("got %q, want the rotated password", after)
	}
}

// A bare reference means "my own project" — the common case, and the one where
// getting the default wrong would silently read another project's secret.
func TestBareReferenceResolvesWithinTheDerivingProject(t *testing.T) {
	v := vault{"drydock/USER": "drydock_user", "other/USER": "WRONG"}
	got, err := Resolve(Ref{Project: "drydock", Name: "DSN"}, "u={{USER}}", v.look)
	if err != nil {
		t.Fatal(err)
	}
	if got != "u=drydock_user" {
		t.Errorf("got %q", got)
	}
}

func TestResolveChainsThroughDerivedInputs(t *testing.T) {
	v := vault{
		"p/BASE":  "b",
		"p/MID":   "=[{{BASE}}]",
		"p/OUTER": "=<{{MID}}>",
	}
	got, err := Resolve(Ref{Project: "p", Name: "OUTER"}, "=<{{MID}}>"[1:], v.look)
	if err != nil {
		t.Fatal(err)
	}
	if got != "<[b]>" {
		t.Errorf("got %q, want %q", got, "<[b]>")
	}
}

func TestResolveDetectsCycles(t *testing.T) {
	cases := map[string]struct {
		v      vault
		origin Ref
		tmpl   string
	}{
		"self": {
			v:      vault{"p/A": "={{A}}"},
			origin: Ref{Project: "p", Name: "A"},
			tmpl:   "{{A}}",
		},
		"mutual": {
			v:      vault{"p/A": "={{B}}", "p/B": "={{A}}"},
			origin: Ref{Project: "p", Name: "A"},
			tmpl:   "{{B}}",
		},
		"cross-project": {
			v:      vault{"x/A": "={{y/B}}", "y/B": "={{x/A}}"},
			origin: Ref{Project: "x", Name: "A"},
			tmpl:   "{{y/B}}",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Resolve(tc.origin, tc.tmpl, tc.v.look)
			if err == nil {
				t.Fatal("cycle resolved instead of erroring")
			}
			if !strings.Contains(err.Error(), "cycle") {
				t.Errorf("error does not name the problem: %v", err)
			}
			// The path is what makes a cycle fixable rather than just reported.
			if !strings.Contains(err.Error(), "→") {
				t.Errorf("cycle error does not show the chain: %v", err)
			}
		})
	}
}

// A missing input has to name the secret that wanted it. An operator reading a
// failed render otherwise has to guess which of a project's entries asked.
func TestMissingInputNamesBothEnds(t *testing.T) {
	_, err := Resolve(Ref{Project: "drydock", Name: "DSN"}, "{{construct-server/GONE}}", vault{}.look)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"drydock/DSN", "construct-server/GONE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestParseRejectsMalformedTemplates(t *testing.T) {
	cases := map[string]string{
		"no references":  "postgres://u:p@h/db",
		"unterminated":   "u={{NAME",
		"empty ref":      "u={{}}",
		"whitespace":     "u={{a b}}",
		"too many parts": "u={{a/b/c}}",
		"empty project":  "u={{/NAME}}",
		"empty name":     "u={{project/}}",
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(tmpl); err == nil {
				t.Fatalf("Parse(%q) accepted a malformed template", tmpl)
			}
		})
	}
}

// The no-references rejection is the one that needs its reasoning in the
// message: it is the only case where the template is well-formed and still
// refused, so "why not" has to be answerable from the error alone.
func TestConstantTemplateExplainsItself(t *testing.T) {
	_, err := Parse("just-a-literal")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "signet set") {
		t.Errorf("error does not point at the operation to use instead: %v", err)
	}
}

func TestRefsReportsEveryReferenceInOrder(t *testing.T) {
	tp, err := Parse("{{A}}:{{p/B}}@{{A}}")
	if err != nil {
		t.Fatal(err)
	}
	got := tp.Refs()
	want := []Ref{{Name: "A"}, {Project: "p", Name: "B"}, {Name: "A"}}
	if len(got) != len(want) {
		t.Fatalf("got %d refs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ref %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
