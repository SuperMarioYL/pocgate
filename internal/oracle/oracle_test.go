package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const buildOnlySpec = `target:
  name: fixture
  build: "true"
`

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSpec(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "pocgate.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCaptureWritesBaseline(t *testing.T) {
	dir := t.TempDir()
	// One executable PoC and one non-executable script: both invocation paths
	// must work, because git checkouts do not always preserve the mode.
	writeFile(t, dir, "alpha.sh", "#!/bin/sh\necho alpha\nexit 0\n", 0o755)
	writeFile(t, dir, "beta.sh", "#!/bin/sh\nexit 0\n", 0o644)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: alpha
    poc: alpha.sh
  - id: beta
    poc: beta.sh
`)

	baseline, err := Capture(context.Background(), specPath, Options{Version: "test"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !baseline.Captured() {
		t.Fatal("Captured() = false, want true")
	}
	if len(baseline.Oracles) != 2 {
		t.Fatalf("got %d oracles, want 2", len(baseline.Oracles))
	}
	for _, result := range baseline.Oracles {
		if result.Fired != 3 || result.Repeats != 3 || len(result.Runs) != 3 {
			t.Errorf("%s: fired=%d repeats=%d runs=%d, want 3/3/3",
				result.ID, result.Fired, result.Repeats, len(result.Runs))
		}
		if len(result.PoCSHA256) != 64 {
			t.Errorf("%s: poc_sha256 = %q, want 64 hex characters", result.ID, result.PoCSHA256)
		}
	}
	if baseline.Env.POCGateVersion != "test" || baseline.Env.StartedAt == "" || baseline.Env.EndedAt == "" {
		t.Errorf("env = %+v, want version and timestamps", baseline.Env)
	}

	wantPath := filepath.Join(dir, ".pocgate", "baseline.json")
	if baseline.Path != wantPath {
		t.Errorf("Path = %q, want %q", baseline.Path, wantPath)
	}
	data, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var stored Baseline
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("baseline is not valid JSON: %v", err)
	}
	if len(stored.Oracles) != 2 || !stored.Captured() {
		t.Errorf("stored baseline = %+v, want two captured oracles", stored)
	}

	var report bytes.Buffer
	baseline.Report(&report)
	if !strings.Contains(report.String(), "alpha: FIRED 3/3") ||
		!strings.Contains(report.String(), "baseline captured") {
		t.Errorf("report = %q, want FIRED 3/3 and the captured marker", report.String())
	}
}

func TestCaptureInconclusiveRefusesBaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "silent.sh", "#!/bin/sh\nexit 1\n", 0o755)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: silent
    poc: silent.sh
`)

	// Pre-seed a baseline from an earlier run. An INCONCLUSIVE run must not
	// leave it behind claiming the PoCs fired.
	baselinePath := filepath.Join(dir, ".pocgate", "baseline.json")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, []byte(`{"oracles":[{"id":"silent","fired":3}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	baseline, err := Capture(context.Background(), specPath, Options{})
	if !errors.Is(err, ErrInconclusive) {
		t.Fatalf("Capture error = %v, want ErrInconclusive", err)
	}
	if baseline == nil {
		t.Fatal("Capture returned no observation; the report needs the fired counts")
	}
	if baseline.Captured() {
		t.Error("Captured() = true for a PoC that never fired")
	}
	if got := baseline.Oracles[0].Fired; got != 0 {
		t.Errorf("fired = %d, want 0", got)
	}
	if !strings.Contains(err.Error(), "silent") {
		t.Errorf("error = %v, want the silent oracle named", err)
	}

	if _, statErr := os.Stat(baselinePath); !os.IsNotExist(statErr) {
		t.Fatalf("previous baseline still exists (stat error %v); an INCONCLUSIVE run must invalidate it", statErr)
	}
}

func TestCaptureStdoutPattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hit.sh", "#!/bin/sh\necho BYPASS\nexit 0\n", 0o755)
	writeFile(t, dir, "miss.sh", "#!/bin/sh\necho blocked\nexit 0\n", 0o755)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: hit
    poc: hit.sh
    fired_when:
      stdout: BYPASS
  - id: miss
    poc: miss.sh
    fired_when:
      stdout: BYPASS
`)

	baseline, err := Capture(context.Background(), specPath, Options{})
	if !errors.Is(err, ErrInconclusive) {
		t.Fatalf("Capture error = %v, want ErrInconclusive", err)
	}
	if got := baseline.Oracles[0].Fired; got != 3 {
		t.Errorf("hit fired = %d, want 3", got)
	}
	if got := baseline.Oracles[1].Fired; got != 0 {
		t.Errorf("miss fired = %d, want 0", got)
	}
}

// TestCaptureCountsUnobserved separates the declared silent exit from every
// other non-fire exit. Only the declared one is silence; the rest prove nothing,
// which is what stops a broken build from reading as a fixed one.
func TestCaptureCountsUnobserved(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "silent.sh", "#!/bin/sh\nexit 1\n", 0o755)
	writeFile(t, dir, "broken.sh", "#!/bin/sh\nexit 3\n", 0o755)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: silent
    poc: silent.sh
    fired_when:
      exit: 0
      silent_exit: 1
  - id: broken
    poc: broken.sh
    fired_when:
      exit: 0
      silent_exit: 1
`)

	baseline, err := Capture(context.Background(), specPath, Options{})
	if !errors.Is(err, ErrInconclusive) {
		t.Fatalf("Capture error = %v, want ErrInconclusive", err)
	}
	if baseline == nil {
		t.Fatal("Capture returned no observation")
	}
	silent, broken := baseline.Oracles[0], baseline.Oracles[1]
	if silent.Fired != 0 || silent.Unobserved != 0 {
		t.Errorf("silent = fired %d, unobserved %d; want 0/0 for the declared silent exit", silent.Fired, silent.Unobserved)
	}
	if broken.Fired != 0 || broken.Unobserved != broken.Repeats {
		t.Errorf("broken = fired %d, unobserved %d; want 0/%d", broken.Fired, broken.Unobserved, broken.Repeats)
	}
	if baseline.Captured() {
		t.Error("Captured() = true; a baseline needs every run to fire")
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".pocgate", "baseline.json")); !os.IsNotExist(statErr) {
		t.Fatalf("baseline file exists or stat failed (%v); an inconclusive run must write nothing", statErr)
	}
}

func TestCaptureNonZeroFireExit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poc.sh", "#!/bin/sh\nexit 2\n", 0o755)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: custom
    poc: poc.sh
    fired_when:
      exit: 2
`)

	baseline, err := Capture(context.Background(), specPath, Options{})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !baseline.Captured() {
		t.Fatal("Capture did not record a baseline for the configured exit code")
	}
}

func TestCaptureBuildFailureWritesNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poc.sh", "#!/bin/sh\nexit 0\n", 0o755)
	specPath := writeSpec(t, dir, `target:
  name: fixture
  build: "exit 7"
oracles:
  - id: a
    poc: poc.sh
`)

	// A stale baseline must not survive an error path either.
	baselinePath := filepath.Join(dir, ".pocgate", "baseline.json")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, []byte(`{"oracles":[{"id":"a","fired":3}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	baseline, err := Capture(context.Background(), specPath, Options{})
	if err == nil {
		t.Fatal("Capture succeeded despite a failing build")
	}
	if errors.Is(err, ErrInconclusive) {
		t.Fatalf("build failure reported as INCONCLUSIVE: %v", err)
	}
	if !strings.Contains(err.Error(), "build target") {
		t.Errorf("error = %v, want it to name the build step", err)
	}
	if baseline != nil {
		t.Errorf("baseline = %+v, want nil when the target was never built", baseline)
	}
	if _, statErr := os.Stat(baselinePath); !os.IsNotExist(statErr) {
		t.Fatalf("previous baseline still exists (stat error %v); a failed run must invalidate it", statErr)
	}
}

func TestCaptureWaitsForServicePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	writeFile(t, dir, "poc.sh", "#!/bin/sh\nexit 0\n", 0o755)
	specPath := writeSpec(t, dir, fmt.Sprintf(`target:
  name: fixture
  build: "true"
  service:
    cmd: "sleep 30"
    port: %d
    ready_timeout_sec: 5
oracles:
  - id: a
    poc: poc.sh
`, port))

	baseline, err := Capture(context.Background(), specPath, Options{})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if baseline.Target.Port != port || baseline.Target.Service != "sleep 30" {
		t.Errorf("target = %+v, want the declared service on port %d", baseline.Target, port)
	}
}

func TestCaptureServiceExitsBeforeReady(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poc.sh", "#!/bin/sh\nexit 0\n", 0o755)
	specPath := writeSpec(t, dir, `target:
  name: fixture
  build: "true"
  service:
    cmd: "exit 3"
    port: 1
    ready_timeout_sec: 2
oracles:
  - id: a
    poc: poc.sh
`)

	_, err := Capture(context.Background(), specPath, Options{})
	if err == nil || !strings.Contains(err.Error(), "service exited") {
		t.Fatalf("Capture error = %v, want service-exited-before-ready", err)
	}
}

func TestCaptureOracleTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hang.sh", "#!/bin/sh\nexec sleep 30\n", 0o755)
	specPath := writeSpec(t, dir, buildOnlySpec+`oracles:
  - id: hang
    poc: hang.sh
    timeout_sec: 1
`)

	start := time.Now()
	_, err := Capture(context.Background(), specPath, Options{})
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Capture error = %v, want an oracle timeout", err)
	}
	if errors.Is(err, ErrInconclusive) {
		t.Errorf("timeout reported as INCONCLUSIVE: %v", err)
	}
	if elapsed > 15*time.Second {
		t.Errorf("Capture took %s, want the 1s oracle budget to cut it short", elapsed)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".pocgate", "baseline.json")); !os.IsNotExist(statErr) {
		t.Fatalf("baseline file exists or stat failed (%v); a timed-out run must write nothing", statErr)
	}
}

func TestCaptureBuildTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "poc.sh", "#!/bin/sh\nexit 0\n", 0o755)
	specPath := writeSpec(t, dir, `target:
  name: fixture
  build: "sleep 30"
  build_timeout_sec: 1
oracles:
  - id: a
    poc: poc.sh
`)

	start := time.Now()
	_, err := Capture(context.Background(), specPath, Options{})
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "build target: timed out") {
		t.Fatalf("Capture error = %v, want a build timeout", err)
	}
	if elapsed > 15*time.Second {
		t.Errorf("Capture took %s, want the 1s build budget to cut it short", elapsed)
	}
}

func TestCaptureStopsServiceAfterFailure(t *testing.T) {
	// Hold a port so readiness succeeds without the service listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	writeFile(t, dir, "silent.sh", "#!/bin/sh\nexit 1\n", 0o755)
	specPath := writeSpec(t, dir, fmt.Sprintf(`target:
  name: fixture
  build: "true"
  service:
    cmd: "echo $$ > svc.pid && exec sleep 30"
    port: %d
    ready_timeout_sec: 5
oracles:
  - id: silent
    poc: silent.sh
`, port))

	_, err = Capture(context.Background(), specPath, Options{})
	if !errors.Is(err, ErrInconclusive) {
		t.Fatalf("Capture error = %v, want ErrInconclusive", err)
	}

	data, readErr := os.ReadFile(filepath.Join(dir, "svc.pid"))
	if readErr != nil {
		t.Fatalf("read service pid: %v", readErr)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if convErr != nil {
		t.Fatalf("service pid %q is not a number: %v", data, convErr)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if killErr := syscall.Kill(pid, 0); errors.Is(killErr, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("service process %d survived Capture; its process group was not stopped", pid)
}
