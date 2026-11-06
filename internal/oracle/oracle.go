// Package oracle replays each declared PoC against the vulnerable build and
// records the pre-patch observation. The baseline is only valid when every PoC
// fires on every run; otherwise the result is INCONCLUSIVE and no baseline is
// written.
package oracle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SuperMarioYL/pocgate/internal/exec"
	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/tree"
)

// ErrInconclusive marks a baseline that cannot prove the vulnerable build
// reproduces the flaw. Callers must not treat it as a tool failure: it is the
// gate refusing to proceed on evidence that would later read as "fixed".
var ErrInconclusive = errors.New("a PoC did not fire on every run of the vulnerable build")

// Options are the non-spec inputs to a baseline capture.
type Options struct {
	// Version is the running pocgate version, recorded in the baseline env.
	Version string
}

// Run is one execution of a PoC.
type Run struct {
	ExitCode     int    `json:"exit"`
	StdoutSHA256 string `json:"stdout_sha256"`
	DurationMS   int64  `json:"duration_ms"`
}

// Result is the aggregate observation for one oracle. Fired and Unobserved are
// counts over Repeats; the remaining runs were deliberately silent (they
// exited with the spec's declared silent_exit).
type Result struct {
	ID         string `json:"id"`
	PoC        string `json:"poc"`
	PoCSHA256  string `json:"poc_sha256"`
	Repeats    int    `json:"repeats"`
	Fired      int    `json:"fired"`
	Unobserved int    `json:"unobserved"`
	Runs       []Run  `json:"runs"`
}

// Target records what the baseline was captured against.
type Target struct {
	Name    string `json:"name"`
	Build   string `json:"build"`
	Service string `json:"service,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// Env records the capture environment so a later reader can reproduce it.
type Env struct {
	POCGateVersion string `json:"pocgate_version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	StartedAt      string `json:"started_at"`
	EndedAt        string `json:"ended_at"`
}

// Baseline is the `.pocgate/baseline.json` record. TreeSHA256 is the digest of
// the exact source tree the PoCs observed, computed with the same rules the
// gate uses for the pre-patch side; a baseline whose tree no longer matches the
// working tree describes different files and cannot support a closure.
type Baseline struct {
	SpecSHA256 string   `json:"spec_sha256"`
	TreeSHA256 string   `json:"tree_sha256"`
	Target     Target   `json:"target"`
	Oracles    []Result `json:"oracles"`
	Env        Env      `json:"env"`

	// Path is where the record was written. It is not part of the JSON.
	Path string `json:"-"`
}

// Captured reports whether every PoC fired on every run and no run was
// unobserved.
func (b *Baseline) Captured() bool {
	if len(b.Oracles) == 0 {
		return false
	}
	for _, r := range b.Oracles {
		if r.Fired != r.Repeats || r.Unobserved != 0 {
			return false
		}
	}
	return true
}

// Report prints one line per oracle in the terminal form the gate promises.
func (b *Baseline) Report(w io.Writer) {
	captured := b.Captured()
	for _, r := range b.Oracles {
		suffix := ""
		if captured {
			suffix = " — baseline captured"
		}
		if r.Unobserved > 0 {
			suffix += fmt.Sprintf(" — UNOBSERVED %d/%d", r.Unobserved, r.Repeats)
		}
		fmt.Fprintf(w, "%s: FIRED %d/%d (exit %d, %s)%s\n",
			r.ID, r.Fired, r.Repeats, r.lastExit(), r.totalDuration(), suffix)
	}
}

func (r Result) lastExit() int {
	if len(r.Runs) == 0 {
		return 0
	}
	return r.Runs[len(r.Runs)-1].ExitCode
}

func (r Result) totalDuration() time.Duration {
	var total int64
	for _, run := range r.Runs {
		total += run.DurationMS
	}
	return (time.Duration(total) * time.Millisecond).Round(100 * time.Millisecond)
}

// Capture builds the target, starts its service, runs every PoC the declared
// number of times, and writes the baseline only when all of them fired. A
// baseline from an earlier run is removed before observing, so a run that fails
// or is inconclusive cannot leave a stale claim behind.
//
// When a PoC does not fire, Capture returns the partial observation together
// with an error wrapping ErrInconclusive. Other errors mean the gate could not
// observe the target at all.
func Capture(ctx context.Context, specPath string, opts Options) (*Baseline, error) {
	sp, err := spec.Load(specPath)
	if err != nil {
		return nil, err
	}

	// A baseline only describes the run that wrote it. Removing any earlier
	// record before observing means a failed or inconclusive run cannot leave a
	// stale "fired: 3" claim behind for a later verify to consume.
	path := filepath.Join(sp.Dir, ".pocgate", "baseline.json")
	if err := invalidateBaseline(path); err != nil {
		return nil, fmt.Errorf("invalidate previous baseline: %w", err)
	}

	baseline, err := Observe(ctx, sp, opts)
	if err != nil {
		return baseline, err
	}

	var silent []string
	for _, r := range baseline.Oracles {
		if r.Fired != r.Repeats {
			silent = append(silent, r.ID)
		}
	}
	if len(silent) > 0 {
		return baseline, fmt.Errorf("%w: %s", ErrInconclusive, strings.Join(silent, ", "))
	}

	if err := writeBaseline(path, baseline); err != nil {
		return nil, fmt.Errorf("write baseline: %w", err)
	}
	baseline.Path = path
	return baseline, nil
}

// Observe builds the target, starts its service when one is declared, and runs
// every PoC its declared number of times. It writes nothing: Capture turns the
// observation into the baseline record, and verify reuses it against the patched
// copy.
//
// When an oracle cannot be run Observe returns the partial observation with the
// error; deciding whether a PoC fired is the caller's business.
func Observe(ctx context.Context, sp *spec.Spec, opts Options) (*Baseline, error) {
	specSum, err := fileSHA256(sp.Path)
	if err != nil {
		return nil, err
	}
	started := time.Now().UTC()

	buildCtx, cancelBuild := context.WithTimeout(ctx, sp.Target.BuildTimeout())
	build, err := exec.RunShell(buildCtx, sp.Dir, sp.Target.Build, nil)
	cancelBuild()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("build target: timed out after %s", sp.Target.BuildTimeout())
		}
		return nil, fmt.Errorf("build target: %w", err)
	}
	if build.ExitCode != 0 {
		return nil, fmt.Errorf("build target: %q exited %d%s",
			sp.Target.Build, build.ExitCode, stderrHint(build.Stderr))
	}
	// Digest the tree the PoCs are about to probe, build artifacts included.
	// Recording it here is what lets verify reject a baseline captured before
	// the working tree changed: without it the patch would be credited with a
	// closure that the tree, not the patch, produced.
	treeSum, err := tree.SHA256(sp.Dir)
	if err != nil {
		return nil, fmt.Errorf("digest target tree: %w", err)
	}

	service := sp.Target.Service
	if service.Enabled() {
		svc, err := exec.StartService(sp.Dir, service.Cmd, service.Env)
		if err != nil {
			return nil, fmt.Errorf("start service: %w", err)
		}
		defer svc.Stop()
		if err := svc.WaitReady(ctx, service.Port, service.ReadyTimeout()); err != nil {
			return nil, err
		}
	}

	baseline := &Baseline{
		SpecSHA256: specSum,
		TreeSHA256: treeSum,
		Target: Target{
			Name:    sp.Target.Name,
			Build:   sp.Target.Build,
			Service: service.Cmd,
			Port:    service.Port,
		},
		Oracles: make([]Result, 0, len(sp.Oracles)),
		Env: Env{
			POCGateVersion: opts.Version,
			OS:             runtime.GOOS,
			Arch:           runtime.GOARCH,
			StartedAt:      started.Format(time.RFC3339),
		},
	}

	for _, o := range sp.Oracles {
		oracleCtx, cancel := context.WithTimeout(ctx, o.Timeout())
		result, err := replay(oracleCtx, sp.Dir, o)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return baseline, fmt.Errorf("oracle %s: timed out after %s", o.ID, o.Timeout())
			}
			return baseline, fmt.Errorf("oracle %s: %w", o.ID, err)
		}
		baseline.Oracles = append(baseline.Oracles, result)
	}
	baseline.Env.EndedAt = time.Now().UTC().Format(time.RFC3339)
	return baseline, nil
}

func replay(ctx context.Context, dir string, o spec.Oracle) (Result, error) {
	pocSum, err := fileSHA256(o.PoCFile())
	if err != nil {
		return Result{}, err
	}
	result := Result{
		ID:        o.ID,
		PoC:       o.PoC,
		PoCSHA256: pocSum,
		Repeats:   o.Repeats,
		Runs:      make([]Run, 0, o.Repeats),
	}
	for i := 0; i < o.Repeats; i++ {
		run, err := exec.RunFile(ctx, dir, o.PoCFile(), o.Env)
		if err != nil {
			return Result{}, fmt.Errorf("run %s: %w", o.PoC, err)
		}
		result.Runs = append(result.Runs, Run{
			ExitCode:     run.ExitCode,
			StdoutSHA256: run.StdoutSHA256,
			DurationMS:   run.Duration.Milliseconds(),
		})
		switch o.FiredWhen.Outcome(run.ExitCode, run.Stdout) {
		case spec.Fired:
			result.Fired++
		case spec.Unobserved:
			result.Unobserved++
		}
	}
	return result, nil
}

// invalidateBaseline removes a baseline left by an earlier run. A missing file
// is the normal first-run case; any other error means the gate cannot promise
// the record it leaves behind describes this run, so it must not proceed.
func invalidateBaseline(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeBaseline(path string, b *Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".baseline-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func stderrHint(stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	if s == "" {
		return ""
	}
	if len(s) > 2000 {
		s = "..." + s[len(s)-2000:]
	}
	return "\n" + s
}
