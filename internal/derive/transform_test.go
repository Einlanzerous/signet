package derive

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func resolveFor(t *testing.T, v fakeVault, tmpl string) string {
	t.Helper()
	got, err := Resolve(Ref{Project: "p", Name: "OUT"}, tmpl, v.look, testKey)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", tmpl, err)
	}
	return got
}

// The encodings, against values worked out independently of the code: the
// basic-auth header and the Kubernetes data field are the two uses the ticket
// names.
func TestEncodingTransformsProduceTheReferencedValueEncoded(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2", "p/BIN": "\xff\x00\xfe"}
	for tmpl, want := range map[string]string{
		"{{PW | base64}}":                "aHVudGVyMg==",
		"Bearer {{PW | base64}}":         "Bearer aHVudGVyMg==",
		"{{PW | hex}}":                   "68756e74657232",
		"{{PW}}/{{PW | base64}}":         "hunter2/aHVudGVyMg==",
		"{{PW | base64}}.{{PW | hex}}":   "aHVudGVyMg==.68756e74657232",
		"{{ PW | base64 }}":              "aHVudGVyMg==",
		"{{p/PW | base64}}":              "aHVudGVyMg==",
		"{{BIN | hex}}":                  "ff00fe",
		"{{BIN | base64}}":               "/wD+",
		"{{PW | base64}}{{PW | base64}}": "aHVudGVyMg==aHVudGVyMg==",
	} {
		if got := resolveFor(t, v, tmpl); got != want {
			t.Errorf("%s = %q, want %q", tmpl, got, want)
		}
	}
}

// Basic auth is base64 of user:password, which is a transform over a
// composition, not over one reference. It is expressible by deriving the pair
// and then encoding that — the reason one transform per reference is enough.
func TestATransformOfADerivedInputEncodesTheComposedValue(t *testing.T) {
	v := fakeVault{"p/USER": "svc", "p/PW": "hunter2", "p/PAIR": "={{USER}}:{{PW}}"}
	got := resolveFor(t, v, "Basic {{PAIR | base64}}")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:hunter2"))
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The cache holds a reference's value before any transform. If it held the
// transformed one, the plain reference after a transformed one would render the
// encoding, and the reverse order would encode an already-plain value once and
// an encoded one the next time.
func TestATransformDoesNotLeakIntoTheMemoizedValue(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2"}
	for tmpl, want := range map[string]string{
		"{{PW | base64}}|{{PW}}": "aHVudGVyMg==|hunter2",
		"{{PW}}|{{PW | base64}}": "hunter2|aHVudGVyMg==",
	} {
		if got := resolveFor(t, v, tmpl); got != want {
			t.Errorf("%s = %q, want %q", tmpl, got, want)
		}
	}
}

// A transformed reference is still an input. The rotation impact report, the
// dependency graph and the disclosure audit all read Refs, and one that dropped
// transformed references would report a hashed input as not an input at all —
// under-reporting what a rotation changed, which is the failure derivations
// exist to prevent.
func TestRefsReportsATransformedReference(t *testing.T) {
	tp, err := Parse("a={{A}} b={{p/B | scrypt}} c={{C | base64}}")
	if err != nil {
		t.Fatal(err)
	}
	want := []Ref{{Name: "A"}, {Project: "p", Name: "B"}, {Name: "C"}}
	got := tp.Refs()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ref %d: got %v, want %v", i, got[i], want[i])
		}
	}
	uses := tp.Uses()
	for i, wantT := range []string{"", "scrypt", "base64"} {
		if uses[i].Transform != wantT {
			t.Errorf("use %d: transform %q, want %q", i, uses[i].Transform, wantT)
		}
	}
}

// Names are not validated anywhere in this codebase, so a secret may be called
// a|b or a:b. The transform marker must not change what such a reference means:
// it is a pipe set off by whitespace, and whitespace inside a reference was
// already an error, so no stored template can hold one.
func TestTheTransformMarkerIsUnambiguousAgainstNamesContainingDelimiters(t *testing.T) {
	cases := map[string]struct {
		ref       Ref
		transform string
	}{
		"{{a|b}}":              {Ref{Name: "a|b"}, ""},
		"{{a:b}}":              {Ref{Name: "a:b"}, ""},
		"{{scrypt:PW}}":        {Ref{Name: "scrypt:PW"}, ""},
		"{{x|base64}}":         {Ref{Name: "x|base64"}, ""},
		"{{p:q/a|b}}":          {Ref{Project: "p:q", Name: "a|b"}, ""},
		"{{p:q/a|b | base64}}": {Ref{Project: "p:q", Name: "a|b"}, "base64"},
		"{{scrypt:PW | hex}}":  {Ref{Name: "scrypt:PW"}, "hex"},
	}
	for tmpl, want := range cases {
		tp, err := Parse(tmpl)
		if err != nil {
			t.Errorf("Parse(%q): %v", tmpl, err)
			continue
		}
		u := tp.Uses()
		if len(u) != 1 || u[0].Ref != want.ref || u[0].Transform != want.transform {
			t.Errorf("Parse(%q) = %+v, want ref %v transform %q", tmpl, u, want.ref, want.transform)
		}
	}
}

func TestParseRejectsMalformedTransforms(t *testing.T) {
	cases := map[string]string{
		"pipe with no transform":  "{{A |}}",
		"pipe then space":         "{{A | }}",
		"two transforms":          "{{A | base64 | hex}}",
		"transform without pipe":  "{{A base64}}",
		"pipe glued to transform": "{{A |base64}}",
		"no reference":            "{{ | base64}}",
		"stray word after":        "{{A | base64 extra}}",
		"transform, bad ref":      "{{a/b/c | base64}}",
		"transform, empty name":   "{{p/ | base64}}",
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(tmpl); err == nil {
				t.Fatalf("Parse(%q) accepted a malformed transform", tmpl)
			}
		})
	}
}

// A template whose only reference is transformed still names a secret, so it is
// not the constant Parse refuses.
func TestATransformedReferenceCountsAsAReference(t *testing.T) {
	if _, err := Parse("{{PW | scrypt}}"); err != nil {
		t.Fatalf("a template of one transformed reference was refused: %v", err)
	}
}

func TestAnUnknownTransformIsRejectedAtDeclarationAndListsWhatExists(t *testing.T) {
	_, err := Parse("{{PW | rot13}}")
	if err == nil {
		t.Fatal("an unknown transform parsed")
	}
	for _, want := range []string{"rot13", "unknown", "base64", "hex", "scrypt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// bcrypt is the case the ticket is about: it cannot be made deterministic, so it
// has to fail when declared. The message is what an operator asking for it has,
// and "unknown transform" would send them off to check their spelling.
func TestBcryptIsRefusedAtDeclarationWithTheReason(t *testing.T) {
	_, err := Parse("{{PW | bcrypt}}")
	if err == nil {
		t.Fatal("bcrypt was accepted — its salt is random, so render --check would report permanent drift")
	}
	for _, want := range []string{"bcrypt", "drift", "scrypt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("a refusal reads as an unknown name: %v", err)
	}
	for _, name := range Transforms() {
		if name == "bcrypt" {
			t.Error("Transforms() lists bcrypt as declarable")
		}
	}
}

// A template stored before a transform was refused, or edited into the database
// by hand, has to fail the way a typed one does — at parse, on every read path,
// rather than resolving to something.
func TestAStoredTemplateNamingARefusedTransformFailsToResolve(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2", "p/OUT": "={{PW | bcrypt}}"}
	if _, err := Resolve(Ref{Project: "p", Name: "TOP"}, "{{OUT}}", v.look, testKey); err == nil {
		t.Fatal("a stored template naming bcrypt resolved")
	}
}

// The property the registry exists to hold, over the registry rather than over
// the transforms someone remembered to list: a transform added later that is not
// deterministic fails here, before it can be declared against a real secret.
func TestEveryRegisteredTransformIsDeterministic(t *testing.T) {
	inputs := []string{"hunter2", "ünïcödé", "\xff\x00"}
	ctx := func() transformCtx {
		return transformCtx{origin: Ref{Project: "p", Name: "OUT"}, key: append([]byte{}, testKey...)}
	}
	seen := 0
	for name, tr := range transforms {
		if tr.refused != "" {
			if tr.apply != nil {
				t.Errorf("%s is refused but has an implementation — one of the two is wrong", name)
			}
			continue
		}
		seen++
		for _, in := range inputs {
			first, err := tr.apply(ctx(), in)
			if err != nil {
				t.Fatalf("%s(%q): %v", name, in, err)
			}
			for i := 0; i < 2; i++ {
				again, err := tr.apply(ctx(), in)
				if err != nil {
					t.Fatalf("%s(%q): %v", name, in, err)
				}
				if again != first {
					t.Errorf("%s(%q) is not deterministic: %q then %q", name, in, first, again)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no transforms are registered; the loop above proved nothing")
	}
}

// Rendering twice, at the layer that renders: the same vault gives the same
// derived value, which is what keeps render --check quiet.
func TestResolvingAScryptDerivationTwiceGivesTheSameValue(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2"}
	first := resolveFor(t, v, "{{PW | scrypt}}")
	if second := resolveFor(t, v, "{{PW | scrypt}}"); second != first {
		t.Fatalf("two resolutions of an unchanged vault differ:\n  %s\n  %s", first, second)
	}
}

// verify is Drydock's verifyPassword, reimplemented from its source
// (daemon/src/auth/password.ts): split on $, read the parameters out of the
// string, recompute, compare. A hash this accepts is one the consumer accepts.
func verify(t *testing.T, password, stored string) bool {
	t.Helper()
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, _ := strconv.Atoi(parts[1])
	r, _ := strconv.Atoi(parts[2])
	p, _ := strconv.Atoi(parts[3])
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := scrypt.Key([]byte(password), salt, n, r, p, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func TestScryptOutputIsInTheFormatDrydockVerifies(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2"}
	got := resolveFor(t, v, "{{PW | scrypt}}")

	parts := strings.Split(got, "$")
	if len(parts) != 6 {
		t.Fatalf("got %d $-separated fields, want 6: %q", len(parts), got)
	}
	if parts[0] != "scrypt" || parts[1] != "16384" || parts[2] != "8" || parts[3] != "1" {
		t.Errorf("header is %v, want scrypt$16384$8$1 as Drydock writes it", parts[:4])
	}
	if salt, err := base64.StdEncoding.DecodeString(parts[4]); err != nil || len(salt) != 16 {
		t.Errorf("salt %q is not 16 bytes of standard base64: %v", parts[4], err)
	}
	if key, err := base64.StdEncoding.DecodeString(parts[5]); err != nil || len(key) != 32 {
		t.Errorf("hash %q is not 32 bytes of standard base64: %v", parts[5], err)
	}
	if !verify(t, "hunter2", got) {
		t.Error("the produced hash does not verify against the password it was made from")
	}
	if verify(t, "hunter3", got) {
		t.Error("the produced hash verifies against a different password")
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("the hash contains the password: %q", got)
	}
}

// The three properties the salt has to have, each of which a plausible simpler
// salt fails: it changes when the password does (a per-secret constant would
// not), it differs between secrets hashing the same value, and it depends on the
// vault key (a salt from the value alone is a precomputable table).
func TestScryptSaltFollowsTheInputTheDerivingSecretAndTheKey(t *testing.T) {
	salt := func(t *testing.T, origin Ref, key []byte, pw string) string {
		t.Helper()
		v := fakeVault{"p/PW": pw}
		out, err := Resolve(origin, "{{p/PW | scrypt}}", v.look, key)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(out, "$")[4]
	}
	base := salt(t, Ref{Project: "p", Name: "A"}, testKey, "hunter2")

	if again := salt(t, Ref{Project: "p", Name: "A"}, testKey, "hunter2"); again != base {
		t.Error("the salt changed between two reads of an unchanged vault")
	}
	if salt(t, Ref{Project: "p", Name: "A"}, testKey, "hunter3") == base {
		t.Error("the salt survived a change of password — a rotation would reuse it")
	}
	if salt(t, Ref{Project: "p", Name: "B"}, testKey, "hunter2") == base {
		t.Error("two secrets hashing the same value share a salt")
	}
	if salt(t, Ref{Project: "q", Name: "A"}, testKey, "hunter2") == base {
		t.Error("the salt does not depend on the deriving secret's project")
	}
	other := append([]byte{}, testKey...)
	other[0] ^= 1
	if salt(t, Ref{Project: "p", Name: "A"}, other, "hunter2") == base {
		t.Error("the salt does not depend on the vault key — anyone can precompute it")
	}
}

// Salting with nothing is still deterministic and would be accepted without
// complaint, so the refusal has to be explicit.
func TestScryptRefusesToSaltWithoutAVaultKey(t *testing.T) {
	v := fakeVault{"p/PW": "hunter2-marker"}
	for _, key := range [][]byte{nil, {}} {
		_, err := Resolve(Ref{Project: "p", Name: "OUT"}, "{{PW | scrypt}}", v.look, key)
		if err == nil {
			t.Fatalf("scrypt produced a hash with key %v", key)
		}
		if strings.Contains(err.Error(), "hunter2-marker") {
			t.Errorf("the error carries the value: %v", err)
		}
	}
}

func TestScryptRefusesAnEmptyValue(t *testing.T) {
	v := fakeVault{"p/PW": ""}
	_, err := Resolve(Ref{Project: "p", Name: "OUT"}, "{{PW | scrypt}}", v.look, testKey)
	if err == nil {
		t.Fatal("scrypt hashed an empty value into a hash that accepts an empty login")
	}
	for _, want := range []string{"p/OUT", "p/PW", "scrypt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

// A cycle through a transformed reference is still a cycle, and is reported as
// one rather than as whatever the transform makes of a partial value.
func TestACycleThroughATransformedReferenceIsStillACycle(t *testing.T) {
	v := fakeVault{"p/A": "={{B | base64}}", "p/B": "={{A}}"}
	_, err := Resolve(Ref{Project: "p", Name: "A"}, "{{B | base64}}", v.look, testKey)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("got %v, want a cycle error", err)
	}
}

func TestTransformsListsWhatCanBeDeclaredSorted(t *testing.T) {
	got := strings.Join(Transforms(), ",")
	if got != "base64,hex,scrypt" {
		t.Errorf("Transforms() = %q", got)
	}
}
