package verdict

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperMarioYL/pocgate/internal/oracle"
	"github.com/SuperMarioYL/pocgate/internal/spec"
)

// fired is the common case: the PoC fired on every pre-patch run and is silent
// after the patch.
func fired(id string) LegObservation {
	return LegObservation{ID: id, Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostFired: 0}
}

func TestDecide(t *testing.T) {
	closedRegression := RegressionObservation{Present: true, NewFailures: []string{}}
	brokenRegression := RegressionObservation{Present: true, NewFailures: []string{"TestAdminStaysPublic"}}
	missingRegression := RegressionObservation{}

	tests := []struct {
		name string
		obs  Observations
		want Verdict
	}{
		{
			name: "all three legs hold",
			obs:  Observations{Oracles: []LegObservation{fired("a"), fired("b")}, Regression: closedRegression},
			want: Closed,
		},
		{
			name: "one oracle still fires",
			obs: Observations{
				Oracles:    []LegObservation{fired("a"), {ID: "b", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostFired: 1}},
				Regression: closedRegression,
			},
			want: StillVulnerable,
		},
		{
			name: "still vulnerable outranks a broken regression",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostFired: 2}},
				Regression: brokenRegression,
			},
			want: StillVulnerable,
		},
		{
			name: "new regression failure",
			obs:  Observations{Oracles: []LegObservation{fired("a")}, Regression: brokenRegression},
			want: RegressionBroken,
		},
		{
			name: "missing pre-patch side",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PostPresent: true, PostFired: 0}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "missing post-patch side",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PreFired: 3}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "post fire without a pre observation is not proof of anything",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PostPresent: true, PostFired: 3}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "missing regression command",
			obs:  Observations{Oracles: []LegObservation{fired("a")}, Regression: missingRegression},
			want: Inconclusive,
		},
		{
			name: "post fire plus missing regression still cannot observe all legs",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostFired: 3}},
				Regression: missingRegression,
			},
			want: Inconclusive,
		},
		{
			name: "no oracles",
			obs:  Observations{Regression: closedRegression},
			want: Inconclusive,
		},
		{
			name: "zero repeats",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 0, PrePresent: true, PostPresent: true}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "silence proves nothing when the PoC did not fire before",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 2}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "a broken regression is real even when the pre leg was weak",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 2}},
				Regression: brokenRegression,
			},
			want: RegressionBroken,
		},
		{
			name: "an unobserved post-patch run is never a closure",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 3}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "one unobserved post-patch run among silent ones is not a closure",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 1}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "an unobserved pre-patch run is not a baseline",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 2, PreUnobserved: 1}},
				Regression: closedRegression,
			},
			want: Inconclusive,
		},
		{
			name: "a fire still outranks an unobserved run",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostFired: 1, PostUnobserved: 2}},
				Regression: closedRegression,
			},
			want: StillVulnerable,
		},
		{
			name: "a broken regression cannot rescue an unobserved leg",
			obs: Observations{
				Oracles:    []LegObservation{{ID: "a", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 1}},
				Regression: brokenRegression,
			},
			want: Inconclusive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.obs); got != tt.want {
				t.Fatalf("Decide() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestAllFiveHundredPatchIsInconclusive is the regression for the critical
// defect: a patch that breaks the service answers every PoC with a 500, so the
// PoCs exit with the unobserved code rather than the declared silent code.
// That silence must never read as CLOSED.
func TestAllFiveHundredPatchIsInconclusive(t *testing.T) {
	obs := Observations{
		Oracles: []LegObservation{
			{ID: "authbypass", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 3},
			{ID: "traversal", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 3},
			{ID: "ssrf", Repeats: 3, PrePresent: true, PostPresent: true, PreFired: 3, PostUnobserved: 3},
		},
		Regression: RegressionObservation{Present: true, NewFailures: []string{}},
	}
	if got := Decide(obs); got != Inconclusive {
		t.Fatalf("Decide() = %s, want INCONCLUSIVE for a build whose PoCs were all unobserved", got)
	}
}

func TestVerdictExitCodes(t *testing.T) {
	tests := []struct {
		verdict Verdict
		want    int
	}{
		{Closed, 0},
		{StillVulnerable, 1},
		{RegressionBroken, 2},
		{Inconclusive, 3},
		{Verdict("SOMETHING_ELSE"), 3},
	}
	for _, tt := range tests {
		if got := tt.verdict.ExitCode(); got != tt.want {
			t.Errorf("%s.ExitCode() = %d, want %d", tt.verdict, got, tt.want)
		}
	}
}

// TestFailOnThreshold covers the --fail-on mapping. The closure-risk order is
// CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE, which is
// deliberately different from the reporting priority: an unobservable run is
// the worst thing to let through a gate, so every threshold fails it.
func TestFailOnThreshold(t *testing.T) {
	tests := []struct {
		verdict   Verdict
		threshold Verdict
		wantFail  bool
	}{
		{Closed, Inconclusive, false},
		{Closed, RegressionBroken, false},
		{Closed, StillVulnerable, false},
		{Inconclusive, Inconclusive, true},
		{Inconclusive, RegressionBroken, true},
		{Inconclusive, StillVulnerable, true},
		{RegressionBroken, Inconclusive, false},
		{RegressionBroken, RegressionBroken, true},
		{RegressionBroken, StillVulnerable, false},
		{StillVulnerable, Inconclusive, false},
		{StillVulnerable, RegressionBroken, true},
		{StillVulnerable, StillVulnerable, true},
	}
	for _, tt := range tests {
		if got := tt.verdict.AtLeastRisk(tt.threshold); got != tt.wantFail {
			t.Errorf("%s.AtLeastRisk(%s) = %t, want %t", tt.verdict, tt.threshold, got, tt.wantFail)
		}
	}
}

func TestParse(t *testing.T) {
	for _, want := range []Verdict{Closed, StillVulnerable, RegressionBroken, Inconclusive} {
		got, err := Parse(string(want))
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v", want, got, err)
		}
	}
	if _, err := Parse("closed"); err == nil {
		t.Error("Parse is case-sensitive; \"closed\" should not be accepted")
	}
	if _, err := Parse("BROKEN"); err == nil {
		t.Error("Parse should reject an unknown verdict")
	}
}

func TestValidatePatchAcceptsTheBundledPatch(t *testing.T) {
	data, err := os.ReadFile("../demo/fixtures/shop/patch.diff")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePatch(data); err != nil {
		t.Fatalf("the bundled patch must be accepted: %v", err)
	}
}

func TestValidatePatch(t *testing.T) {
	tests := []struct {
		name    string
		patch   string
		wantErr bool
		wantMsg string
	}{
		{
			name:  "git style update",
			patch: "--- a/main.go\n+++ b/main.go\n@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n",
		},
		{
			name:  "creation",
			patch: "--- /dev/null\n+++ b/new_test.go\n@@ -0,0 +1 @@\n+package main\n",
		},
		{
			name:  "deletion",
			patch: "--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package main\n",
		},
		{
			name:    "prefix-less diff",
			patch:   "--- main.go\n+++ main.go\n@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n",
			wantErr: true,
			wantMsg: "no a/ path prefix",
		},
		{
			name:    "prefix-less creation",
			patch:   "--- /dev/null\n+++ new.go\n@@ -0,0 +1 @@\n+x\n",
			wantErr: true,
			wantMsg: "no b/ path prefix",
		},
		{
			name:    "path escapes the workspace",
			patch:   "--- a/main.go\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
			wantErr: true,
			wantMsg: "escapes the scratch workspace",
		},
		{
			name:    "absolute path",
			patch:   "--- /etc/passwd\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
			wantErr: true,
			wantMsg: "prefix",
		},
		{
			name:    "empty path component",
			patch:   "--- a//tmp/x\n+++ b/tmp/x\n@@ -1 +1 @@\n-a\n+b\n",
			wantErr: true,
			wantMsg: "empty component",
		},
		{
			name:    "no headers",
			patch:   "this is not a patch at all\n",
			wantErr: true,
			wantMsg: "no ---/+++ file headers",
		},
		{
			name:    "dangling old header",
			patch:   "--- a/main.go\nnot a plus header\n",
			wantErr: true,
			wantMsg: "without a following +++ header",
		},
		{
			name:    "malformed hunk header",
			patch:   "--- a/main.go\n+++ b/main.go\n@@ nonsense @@\n",
			wantErr: true,
			wantMsg: "malformed hunk header",
		},
		{
			// A removed line whose content starts with "-- " renders as "--- ...".
			// Inside a hunk it is body, not a file header.
			name:  "header-like text inside a hunk body",
			patch: "--- a/main.go\n+++ b/main.go\n@@ -1,1 +0,0 @@\n--- removed comment\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePatch([]byte(tt.patch))
			if tt.wantErr {
				if err == nil {
					t.Fatal("validatePatch accepted a patch it should reject")
				}
				if !errors.Is(err, ErrBadPatch) {
					t.Fatalf("error %v does not wrap ErrBadPatch", err)
				}
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Fatalf("error %q does not explain %q", err, tt.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePatch rejected a valid patch: %v", err)
			}
		})
	}
}

func TestDifference(t *testing.T) {
	got := difference([]string{"a", "b"}, []string{"b", "c", "c", "a"})
	want := []string{"c"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("difference() = %v, want %v", got, want)
	}
	if got := difference(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("difference(nil, nil) = %v, want an empty slice", got)
	}
}

// TestRunRejectsStaleBaselineTree is the regression for crediting a patch with
// a closure the working tree produced. Once the tree changes after capture, the
// baseline describes different files and its pre-patch leg must not be used.
func TestRunRejectsStaleBaselineTree(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("poc.sh", "#!/bin/sh\nexit 0\n", 0o755)
	specPath := filepath.Join(dir, "pocgate.yaml")
	write("pocgate.yaml", `target:
  name: fixture
  build: "true"
oracles:
  - id: a
    poc: poc.sh
    repeats: 1
    fired_when:
      exit: 0
      silent_exit: 1
regression:
  cmd: "true"
`, 0o644)

	if _, err := oracle.Capture(context.Background(), specPath, oracle.Options{Version: "test"}); err != nil {
		t.Fatalf("capture baseline: %v", err)
	}

	// The real fix lands in the working tree after the baseline was captured.
	write("main.go", "package main\n", 0o644)

	sp, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	patchPath := filepath.Join(t.TempDir(), "noop.diff")
	if err := os.WriteFile(patchPath, []byte("--- /dev/null\n+++ b/noop.txt\n@@ -0,0 +1 @@\n+noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	doc, err := Run(context.Background(), Request{Spec: sp, PatchPath: patchPath, Version: "test"})
	if err == nil {
		t.Fatalf("Run used a stale baseline and produced %s; want INCONCLUSIVE", doc.Verdict)
	}
	if !errors.Is(err, ErrInconclusive) {
		t.Fatalf("error = %v, want ErrInconclusive", err)
	}
	if !strings.Contains(err.Error(), "tree changed") {
		t.Fatalf("error = %v, want it to name the changed tree", err)
	}
}
