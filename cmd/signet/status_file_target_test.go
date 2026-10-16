package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedEmptyFileTarget registers a file target that manages no keys, by importing
// an env file with nothing in it — the reproduction from SGNT-50. The file is
// then given live content signet does not manage, which is the shape where
// `render --prune` would empty it.
func seedEmptyFileTarget(t *testing.T, project string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.env")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runImport([]string{"--project", project, path}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("LIVE_ONE=1\nLIVE_TWO=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A file target that manages no keys belongs to no secret's row. Before SGNT-50
// that meant `status` did not show it at all, while `target list`, `render` and
// `render --check` all did.
func TestStatusShowsAFileTargetThatManagesNoSecret(t *testing.T) {
	st := newCLIVault(t)
	populated := seedProject(t, st, "demo", map[string]string{"ALPHA": "a"})
	empty := seedEmptyFileTarget(t, "demo")

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})

	// Scoped to the row naming the empty file, so the populated target's row
	// cannot satisfy it.
	row := lineWith(t, out, "file:"+empty)
	if !strings.Contains(row, "(0 keys)") {
		t.Errorf("the row does not say the target manages nothing:\n%s", row)
	}
	if !strings.HasPrefix(strings.TrimSpace(row), "demo") {
		t.Errorf("the row is not filed under its project:\n%s", row)
	}
	// The same word `target list` prints for the whole file, not a new one.
	if !strings.Contains(row, "[in sync]") {
		t.Errorf("the row does not carry the file's state:\n%s", row)
	}

	// The populated target still rides on its secret's row, and gets no subject
	// row of its own.
	alpha := lineWith(t, out, "ALPHA")
	if !strings.Contains(alpha, "file:"+populated) {
		t.Errorf("the populated target left its secret's row:\n%s", alpha)
	}
	if n := strings.Count(out, "file:"+populated); n != 1 {
		t.Errorf("the populated target appears %d times, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "file:"+empty); n != 1 {
		t.Errorf("the empty target appears %d times, want 1:\n%s", n, out)
	}
}

// The row is emitted at a project boundary, so the fixture needs a project
// before and after the one holding the empty target, and one at the end of the
// list: a boundary that fires late files the target under the next project.
func TestStatusFilesEachEmptyFileTargetUnderItsOwnProject(t *testing.T) {
	st := newCLIVault(t)
	seedProject(t, st, "aaa", map[string]string{"A1": "a", "A2": "b"})
	aaa := seedEmptyFileTarget(t, "aaa")
	seedProject(t, st, "mmm", map[string]string{"MID": "m"})
	seedProject(t, st, "zzz", map[string]string{"Z1": "z"})
	zzz := seedEmptyFileTarget(t, "zzz")

	out := captureStdout(t, func() {
		if err := runStatus(nil); err != nil {
			t.Fatal(err)
		}
	})

	for _, tc := range []struct{ project, path string }{{"aaa", aaa}, {"zzz", zzz}} {
		row := lineWith(t, out, "file:"+tc.path)
		if fields := strings.Fields(row); len(fields) == 0 || fields[0] != tc.project {
			t.Errorf("the empty target of %s is filed under the wrong project:\n%s", tc.project, row)
		}
		if n := strings.Count(out, "file:"+tc.path); n != 1 {
			t.Errorf("the empty target of %s appears %d times, want 1:\n%s", tc.project, n, out)
		}
	}
	// And it sits directly after its own project's rows, not after the next's.
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "file:"+aaa) {
			if i == 0 || !strings.HasPrefix(lines[i-1], "aaa") {
				t.Errorf("aaa's empty target does not follow aaa's rows:\n%s", out)
			}
		}
	}
}
