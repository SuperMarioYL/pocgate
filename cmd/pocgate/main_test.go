package main

import (
	"bytes"
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/verdict"
)

func TestRunBaselineBadSpecExitsConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cases := map[string]string{
		"missing spec":  filepath.Join(dir, "absent.yaml"),
		"unknown field": write("unknown.yaml", "target:\n  name: shop\n  build: 'true'\n  bogus: 1\n"),
		"duplicate key": write("duplicate.yaml", "target:\n  name: shop\n  name: other\n  build: 'true'\n"),
		"missing poc":   write("missing-poc.yaml", "target:\n  name: shop\n  build: 'true'\noracles:\n  - id: a\n    poc: absent.sh\n"),
		"empty spec":    write("empty.yaml", ""),
	}

	for name, specPath := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"baseline", "--spec", specPath}, &stdout, &stderr)
			if code != exitConfig {
				t.Fatalf("exit code = %d, want %d (config)\nstderr: %s", code, exitConfig, stderr.String())
			}
			if !strings.Contains(stderr.String(), "configuration error") {
				t.Errorf("stderr = %q, want the configuration error to be named", stderr.String())
			}
		})
	}
}

// TestVerdictExitMapping covers the exit status contract: without --fail-on the
// process mirrors the verdict (0-3); with it the gate is a plain 0/1 at the
// named closure-risk threshold. The risk order is
// CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE, so every
// threshold fails an unobservable run.
func TestVerdictExitMapping(t *testing.T) {
	tests := []struct {
		verdict verdict.Verdict
		failOn  string
		want    int
	}{
		{verdict.Closed, "", 0},
		{verdict.StillVulnerable, "", 1},
		{verdict.RegressionBroken, "", 2},
		{verdict.Inconclusive, "", 3},

		{verdict.Closed, "INCONCLUSIVE", 0},
		{verdict.Inconclusive, "INCONCLUSIVE", 1},
		{verdict.RegressionBroken, "INCONCLUSIVE", 0},
		{verdict.StillVulnerable, "INCONCLUSIVE", 0},

		{verdict.Inconclusive, "REGRESSION_BROKEN", 1},
		{verdict.RegressionBroken, "REGRESSION_BROKEN", 1},
		{verdict.StillVulnerable, "REGRESSION_BROKEN", 1},

		{verdict.Closed, "STILL_VULNERABLE", 0},
		{verdict.RegressionBroken, "STILL_VULNERABLE", 0},
		{verdict.StillVulnerable, "STILL_VULNERABLE", 1},
		{verdict.Inconclusive, "STILL_VULNERABLE", 1},

		{verdict.Closed, "CLOSED", exitUsage},
		{verdict.Closed, "nonsense", exitUsage},
	}

	for _, tt := range tests {
		if got := verdictExit(tt.verdict, tt.failOn); got != tt.want {
			t.Errorf("verdictExit(%s, %q) = %d, want %d", tt.verdict, tt.failOn, got, tt.want)
		}
	}
}

// TestAttestVerifyFailsOnUnknownFile keeps the command's failure mode honest:
// nothing to verify is a verification failure, not a success and not a panic.
// It also pins the required trust anchor: a missing --pubkey is a usage error,
// because a key next to the evidence proves only self-consistency.
func TestAttestVerifyFailsOnUnknownFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"attest", "verify", filepath.Join(t.TempDir(), "absent.json")}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d (usage) without --pubkey\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--pubkey") {
		t.Fatalf("stderr = %q, want the missing trust anchor to be named", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	key := filepath.Join(t.TempDir(), "signer.pub")
	code = run(context.Background(), []string{"attest", "verify", "--pubkey", key, filepath.Join(t.TempDir(), "absent.json")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "FAILED") {
		t.Fatalf("stderr = %q, want the failure to be named", stderr.String())
	}
}

// TestRunInitWritesAUsableStarter guards the template against schema drift: the
// file init writes must load once the PoC it names exists. It also pins the
// refusal to overwrite, so a second init cannot silently discard an operator's
// edits.
func TestRunInitWritesAUsableStarter(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"init"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("init exit code = %d, want 0\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pocgate baseline") {
		t.Errorf("stdout = %q, want the next steps", stdout.String())
	}

	// The starter names pocs/authbypass.sh. Creating it is the operator's part;
	// with it present the template must satisfy the real schema.
	if err := os.MkdirAll(filepath.Join(dir, "pocs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pocs", "authbypass.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := spec.Load(filepath.Join(dir, "pocgate.yaml")); err != nil {
		t.Fatalf("the starter does not load: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"init"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("second init exit code = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "--force") {
		t.Errorf("stderr = %q, want the --force escape hatch to be named", stderr.String())
	}
}

// TestRunDoctor reports on a machine-shaped environment without demanding a
// spec: the happy path runs doctor before init. A broken spec, in contrast, must
// fail as a configuration error, and the reason must reach the operator.
func TestRunDoctor(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"doctor"}, &stdout, &stderr)
	if _, ok := locate(context.Background(), "patch"); !ok {
		t.Skip("patch is not installed, so doctor correctly reports a blocking failure")
	}
	if code != exitOK {
		t.Fatalf("doctor exit code = %d, want 0\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "pocgate.yaml") {
		t.Errorf("stdout = %q, want the missing spec to be called out", stdout.String())
	}

	// The shell check must appear in the report; it is the one tool every spec
	// command is routed through.
	if !strings.Contains(stdout.String(), "shell") {
		t.Errorf("stdout = %q, want the shell check", stdout.String())
	}

	if err := os.WriteFile(filepath.Join(dir, "pocgate.yaml"), []byte("target:\n  name: shop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"doctor"}, &stdout, &stderr); code != exitConfig {
		t.Fatalf("doctor exit code = %d, want %d (config)\nstdout: %s", code, exitConfig, stdout.String())
	}
	if !strings.Contains(stdout.String(), "target.build") {
		t.Errorf("stdout = %q, want the spec problem to be named", stdout.String())
	}
}

// TestRunDoctorMissingPatchExitsInternal is the regression for doctor printing
// [fail] entries while still exiting 0. A missing patch makes verify unable to
// apply any diff, so the README's 70 for an unusable environment must hold.
func TestRunDoctorMissingPatchExitsInternal(t *testing.T) {
	shPath, err := osexec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not installed, so a PATH with sh but without patch cannot be built")
	}

	dir := t.TempDir()
	if err := os.Symlink(shPath, filepath.Join(dir, "sh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"doctor"}, &stdout, &stderr)
	if code != exitInternal {
		t.Fatalf("doctor exit code = %d, want %d (internal)\nstdout: %s\nstderr: %s",
			code, exitInternal, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "[fail]") || !strings.Contains(stdout.String(), "patch") {
		t.Fatalf("stdout = %q, want the missing patch to be named as a failure", stdout.String())
	}
}

// TestRunVerifyJSONBadPatchStillEmitsJSON pins the --json contract: whenever the
// gate cannot write evidence it still emits the documented error object, even
// when the input patch itself is the problem (exit 64).
func TestRunVerifyJSONBadPatchStillEmitsJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "poc.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(dir, "pocgate.yaml")
	if err := os.WriteFile(specPath, []byte(`target:
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
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"verify", "--spec", specPath, "--json",
		"--patch", filepath.Join(dir, "absent.diff"),
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d (usage)\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verdict":"INCONCLUSIVE"`) {
		t.Fatalf("stdout = %q, want the documented error JSON", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"error"`) {
		t.Fatalf("stdout = %q, want the error field", stdout.String())
	}
}

// chdir switches into dir for the duration of the test, because init writes into
// the working directory.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	})
}
