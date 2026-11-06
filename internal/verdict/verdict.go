// Package verdict decides whether a patch closed a vulnerability.
//
// The decision is one conjunction over three legs:
//
//  1. every PoC fired on every run of the vulnerable build,
//  2. no PoC fires on any run of the patched build,
//  3. the regression command gained no new failure.
//
// CLOSED holds only when all three legs hold. A leg that could not be observed
// cannot support a closure claim, so any unobserved run yields INCONCLUSIVE,
// ahead of a broken regression. Among definite observations the reported verdict
// follows the plan's priority:
//
//	STILL_VULNERABLE > REGRESSION_BROKEN > INCONCLUSIVE.
//
// The verdict is the process's exit status, so a gate script can branch on it
// without parsing output:
//
//	0  CLOSED
//	1  STILL_VULNERABLE
//	2  REGRESSION_BROKEN
//	3  INCONCLUSIVE
//
// Run owns the observation half of the gate: it copies the target into a
// scratch directory, applies the patch there, rebuilds, replays the PoCs, and
// runs the regression command on both sides. The target's working tree is never
// written to.
package verdict

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SuperMarioYL/pocgate/internal/evidence"
	"github.com/SuperMarioYL/pocgate/internal/exec"
	"github.com/SuperMarioYL/pocgate/internal/oracle"
	"github.com/SuperMarioYL/pocgate/internal/regress"
	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/tree"
)

// Verdict is one of the four closure outcomes.
type Verdict string

// The four verdicts, in the order the plan states them.
const (
	Closed           Verdict = "CLOSED"
	StillVulnerable  Verdict = "STILL_VULNERABLE"
	RegressionBroken Verdict = "REGRESSION_BROKEN"
	Inconclusive     Verdict = "INCONCLUSIVE"
)

// ErrInconclusive marks a run whose three legs could not all be observed, for
// example a missing baseline, a build failure, or a patch that touches the PoC.
// It is not a tool failure: it is the gate refusing to claim closure.
var ErrInconclusive = errors.New("closure could not be proven")

// ErrBadPatch marks a patch that is not the documented git-style diff, or one
// that does not apply to the target. The operator must fix the input.
var ErrBadPatch = errors.New("patch cannot be applied")

// ExitCode is the process status a verdict maps to. An unrecognized verdict
// fails closed as INCONCLUSIVE.
func (v Verdict) ExitCode() int {
	switch v {
	case Closed:
		return 0
	case StillVulnerable:
		return 1
	case RegressionBroken:
		return 2
	default:
		return 3
	}
}

// ClosureRisk ranks verdicts by how unsafe it is to let them pass a gate:
//
//	CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE
//
// This is deliberately not the reporting priority Decide uses (where
// STILL_VULNERABLE outranks REGRESSION_BROKEN): for --fail-on, an unobservable
// run is the worst outcome, because a gate that cannot see the target must
// never be green.
func (v Verdict) ClosureRisk() int {
	switch v {
	case Closed:
		return 0
	case RegressionBroken:
		return 1
	case StillVulnerable:
		return 2
	case Inconclusive:
		return 3
	default:
		return 4
	}
}

// AtLeastRisk reports whether v's closure risk is at or above threshold's.
func (v Verdict) AtLeastRisk(threshold Verdict) bool {
	return v.ClosureRisk() >= threshold.ClosureRisk()
}

// Parse returns the verdict with the given name.
func Parse(s string) (Verdict, error) {
	switch v := Verdict(s); v {
	case Closed, StillVulnerable, RegressionBroken, Inconclusive:
		return v, nil
	}
	return "", fmt.Errorf("unknown verdict %q", s)
}

// LegObservation is what the gate saw for one PoC. The Present fields
// distinguish "observed zero fires" from "not observed at all": the former can
// support a verdict, the latter cannot. The Unobserved fields count runs whose
// exit was neither the fire code nor the declared silent code, i.e. runs that
// prove nothing about the target.
type LegObservation struct {
	ID             string
	Repeats        int
	PrePresent     bool
	PostPresent    bool
	PreFired       int
	PostFired      int
	PreUnobserved  int
	PostUnobserved int
}

// RegressionObservation is the third leg. Present is false when the spec
// declares no regression command, which makes closure unprovable.
type RegressionObservation struct {
	Present     bool
	NewFailures []string
}

// Observations are everything Decide needs.
type Observations struct {
	Oracles    []LegObservation
	Regression RegressionObservation
}

// Decide applies the three-leg conjunction to the observations.
//
// A missing observation (no baseline side, no patched side, no regression
// command, no oracles, zero repeats) is INCONCLUSIVE before anything else. A
// PoC that still fires after the patch is STILL_VULNERABLE: a fire is a
// definite observation regardless of the other runs. Any unobserved run on
// either side is INCONCLUSIVE, because it could be a crash, a 500, or an
// unreachable port, none of which is a fix. New regression failures are
// REGRESSION_BROKEN. Silence after the patch proves closure only when the PoC
// fired on every pre-patch run and every post-patch run ended in the declared
// silent exit.
func Decide(obs Observations) Verdict {
	if len(obs.Oracles) == 0 || !obs.Regression.Present {
		return Inconclusive
	}
	for _, o := range obs.Oracles {
		if o.Repeats < 1 || !o.PrePresent || !o.PostPresent {
			return Inconclusive
		}
	}
	for _, o := range obs.Oracles {
		if o.PostFired > 0 {
			return StillVulnerable
		}
	}
	for _, o := range obs.Oracles {
		if o.PreUnobserved > 0 || o.PostUnobserved > 0 {
			return Inconclusive
		}
	}
	if len(obs.Regression.NewFailures) > 0 {
		return RegressionBroken
	}
	for _, o := range obs.Oracles {
		if o.PreFired != o.Repeats {
			return Inconclusive
		}
	}
	return Closed
}

// Request is one gate run.
type Request struct {
	// Spec is loaded from the target's own directory.
	Spec *spec.Spec
	// PatchPath is the git-style diff to verify.
	PatchPath string
	// Version is the running pocgate version recorded in the evidence.
	Version string
}

// Run observes the three legs for req and returns the completed evidence
// document, unsigned. Closing runs sign and write it with package evidence.
//
// Everything happens in a temporary copy of the target: the copy is patched,
// rebuilt, and probed, then deleted. The pre-patch PoC side comes from
// .pocgate/baseline.json, which must have been captured against the same spec
// and the same source tree; the regression side is run in the copy before and
// after the patch.
func Run(ctx context.Context, req Request) (*evidence.Document, error) {
	sp := req.Spec
	if sp == nil {
		return nil, errors.New("verdict: no spec")
	}
	started := time.Now().UTC()

	patchData, err := os.ReadFile(req.PatchPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrBadPatch, req.PatchPath, err)
	}
	if err := validatePatch(patchData); err != nil {
		return nil, err
	}
	if sp.Regression.Cmd == "" {
		return nil, fmt.Errorf("%w: spec has no regression command, so the third leg cannot be observed", ErrInconclusive)
	}
	specSum, err := fileSHA256(sp.Path)
	if err != nil {
		return nil, err
	}
	baseline, err := loadBaseline(sp, specSum)
	if err != nil {
		return nil, err
	}

	scratch, err := os.MkdirTemp("", "pocgate-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)

	if err := copyTree(sp.Dir, scratch); err != nil {
		return nil, fmt.Errorf("copy target into a scratch workspace: %w", err)
	}
	preTree, err := tree.SHA256(scratch)
	if err != nil {
		return nil, err
	}
	// The baseline's PoC counts describe the tree it was captured against. If
	// the working tree has changed since then (for example because the real fix
	// was already applied), copying it and verifying a no-op patch would credit
	// the patch with a closure the tree achieved. Only an exact match may use
	// the pre-patch leg.
	if baseline.TreeSHA256 != preTree {
		return nil, fmt.Errorf("%w: the target tree changed since the baseline was captured (baseline %s, working tree %s); re-run pocgate baseline on the vulnerable tree",
			ErrInconclusive, short(baseline.TreeSHA256), short(preTree))
	}
	preRegression, err := regress.Run(ctx, scratch, sp.Regression.Cmd, sp.Regression.Parser)
	if err != nil {
		return nil, fmt.Errorf("%w: regression before the patch: %v", ErrInconclusive, err)
	}

	if err := applyPatch(ctx, scratch, patchData); err != nil {
		return nil, err
	}
	postTree, err := tree.SHA256(scratch)
	if err != nil {
		return nil, err
	}
	if err := requireUnchangedSpec(sp, scratch, specSum); err != nil {
		return nil, err
	}

	scratchSpec, err := spec.Load(filepath.Join(scratch, filepath.Base(sp.Path)))
	if err != nil {
		return nil, fmt.Errorf("%w: reload the copied spec: %v", ErrInconclusive, err)
	}
	post, err := oracle.Observe(ctx, scratchSpec, oracle.Options{Version: req.Version})
	if err != nil {
		return nil, fmt.Errorf("%w: post-patch observation: %v", ErrInconclusive, err)
	}
	postRegression, err := regress.Run(ctx, scratch, scratchSpec.Regression.Cmd, scratchSpec.Regression.Parser)
	if err != nil {
		return nil, fmt.Errorf("%w: regression after the patch: %v", ErrInconclusive, err)
	}

	byID := make(map[string]oracle.Result, len(baseline.Oracles))
	for _, r := range baseline.Oracles {
		byID[r.ID] = r
	}
	legs := make([]LegObservation, 0, len(post.Oracles))
	oracles := make([]evidence.Oracle, 0, len(post.Oracles))
	for _, after := range post.Oracles {
		before, ok := byID[after.ID]
		if !ok {
			return nil, fmt.Errorf("%w: the baseline has no observation for oracle %q", ErrInconclusive, after.ID)
		}
		if before.PoCSHA256 != after.PoCSHA256 {
			return nil, fmt.Errorf("%w: the patch modified PoC %q (baseline %s, patched %s)",
				ErrInconclusive, after.ID, short(before.PoCSHA256), short(after.PoCSHA256))
		}
		legs = append(legs, LegObservation{
			ID:             after.ID,
			Repeats:        after.Repeats,
			PrePresent:     len(before.Runs) > 0,
			PostPresent:    len(after.Runs) > 0,
			PreFired:       before.Fired,
			PostFired:      after.Fired,
			PreUnobserved:  before.Unobserved,
			PostUnobserved: after.Unobserved,
		})
		oracles = append(oracles, evidence.Oracle{
			ID:        after.ID,
			PoCSHA256: after.PoCSHA256,
			Repeats:   after.Repeats,
			Pre:       sideOf(before),
			Post:      sideOf(after),
		})
	}

	newFailures := difference(preRegression.FailedIDs, postRegression.FailedIDs)
	decision := Decide(Observations{
		Oracles:    legs,
		Regression: RegressionObservation{Present: true, NewFailures: newFailures},
	})

	return &evidence.Document{
		Verdict: string(decision),
		Target: evidence.Target{
			Name:           sp.Target.Name,
			PatchSHA256:    sha256Hex(patchData),
			PreTreeSHA256:  preTree,
			PostTreeSHA256: postTree,
			BuildCmd:       sp.Target.Build,
		},
		Oracles: oracles,
		Regression: evidence.Regression{
			Cmd:         sp.Regression.Cmd,
			Parser:      sp.Regression.Parser,
			Pre:         testSetOf(preRegression),
			Post:        testSetOf(postRegression),
			NewFailures: newFailures,
		},
		Labels: evidence.Labels{CVE: sp.Labels.CVE, Technique: sp.Labels.Technique},
		Env: evidence.Env{
			POCGateVersion: req.Version,
			OS:             runtime.GOOS,
			RuntimeProbe:   map[string]string{"go": runtime.Version()},
			StartedAt:      started.Format(time.RFC3339),
			EndedAt:        time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// sideOf aggregates one oracle's repeats for the evidence document.
func sideOf(r oracle.Result) evidence.Side {
	side := evidence.Side{Fired: r.Fired}
	for _, run := range r.Runs {
		side.DurationMS += run.DurationMS
	}
	if len(r.Runs) > 0 {
		last := r.Runs[len(r.Runs)-1]
		side.Exit = last.ExitCode
		side.StdoutSHA = last.StdoutSHA256
	}
	return side
}

func testSetOf(r regress.Result) evidence.TestSet {
	failed := r.FailedIDs
	if failed == nil {
		failed = []string{}
	}
	return evidence.TestSet{Total: r.Total, FailedIDs: failed}
}

// difference returns the ids present in after but not in before, in after's
// order. These are the regression failures the patch introduced.
func difference(before, after []string) []string {
	seen := make(map[string]bool, len(before))
	for _, id := range before {
		seen[id] = true
	}
	newIDs := make([]string, 0, len(after))
	for _, id := range after {
		if !seen[id] {
			seen[id] = true
			newIDs = append(newIDs, id)
		}
	}
	return newIDs
}

// loadBaseline reads the pre-patch observation. A missing, stale, or incomplete
// baseline is INCONCLUSIVE: the first leg has no data, so nothing can be closed.
func loadBaseline(sp *spec.Spec, specSum string) (*oracle.Baseline, error) {
	path := filepath.Join(sp.Dir, ".pocgate", "baseline.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: no baseline at %s; run pocgate baseline first", ErrInconclusive, path)
	}
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b oracle.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: baseline %s is not readable JSON: %v", ErrInconclusive, path, err)
	}
	if b.SpecSHA256 != specSum {
		return nil, fmt.Errorf("%w: pocgate.yaml changed since the baseline was captured; re-run pocgate baseline", ErrInconclusive)
	}
	if !b.Captured() {
		return nil, fmt.Errorf("%w: the baseline does not show every PoC firing on every run", ErrInconclusive)
	}
	return &b, nil
}

// requireUnchangedSpec rejects a patch that edits pocgate.yaml: the observation
// would no longer be the one the baseline was captured against.
func requireUnchangedSpec(sp *spec.Spec, scratch, originalSum string) error {
	sum, err := fileSHA256(filepath.Join(scratch, filepath.Base(sp.Path)))
	if err != nil {
		return fmt.Errorf("%w: the patch removed or broke the spec: %v", ErrInconclusive, err)
	}
	if sum != originalSum {
		return fmt.Errorf("%w: the patch modifies %s", ErrInconclusive, filepath.Base(sp.Path))
	}
	return nil
}

// applyPatch writes the diff into the scratch copy and applies it there with
// patch -p1. The file is removed afterwards so it never becomes part of the
// observed tree.
func applyPatch(ctx context.Context, dir string, patch []byte) error {
	const patchFile = ".pocgate-fix.diff"
	path := filepath.Join(dir, patchFile)
	if err := os.WriteFile(path, patch, 0o600); err != nil {
		return fmt.Errorf("stage patch: %w", err)
	}
	defer os.Remove(path)

	res, err := exec.RunShell(ctx, dir, "patch -p1 --batch --forward < "+patchFile, nil)
	if err != nil {
		return fmt.Errorf("apply patch: %w", err)
	}
	if res.ExitCode != 0 {
		hint := strings.TrimSpace(string(res.Stdout) + "\n" + string(res.Stderr))
		return fmt.Errorf("%w: patch exited %d%s", ErrBadPatch, res.ExitCode, hintBlock(hint))
	}
	return nil
}

// validatePatch requires the documented precondition: a git-style unified diff
// whose file headers carry a/ and b/ path prefixes. patch -p1 strips exactly one
// component, so a bare `diff -u` output has nothing to strip and cannot find its
// targets; rejecting it here beats forwarding a patch that must fail.
func validatePatch(data []byte) error {
	lines := strings.Split(string(data), "\n")
	pairs := 0
	oldLeft, newLeft := 0, 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if oldLeft > 0 || newLeft > 0 {
			// Inside a hunk: body lines start with ' ', '-', '+', or '\'.
			// An unprefixed empty line is a context line from some tools.
			switch {
			case strings.HasPrefix(line, "\\"):
			case strings.HasPrefix(line, "-"):
				oldLeft--
			case strings.HasPrefix(line, "+"):
				newLeft--
			case line == "" || strings.HasPrefix(line, " "):
				oldLeft--
				newLeft--
			}
			continue
		}
		if strings.HasPrefix(line, "@@") {
			var err error
			oldLeft, newLeft, err = hunkCounts(line)
			if err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(line, "--- ") {
			continue
		}
		if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
			return badPatch("--- header without a following +++ header on line %d", i+1)
		}
		oldPath := headerPath(line)
		newPath := headerPath(lines[i+1])
		if err := checkPatchPaths(oldPath, newPath); err != nil {
			return err
		}
		pairs++
		i++
	}
	if pairs == 0 {
		return badPatch("no ---/+++ file headers were found")
	}
	return nil
}

// hunkCounts reads the old and new line counts from a @@ header. A missing
// count means one line, per the unified diff format.
func hunkCounts(line string) (oldLeft, newLeft int, err error) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, badPatch("malformed hunk header %q", line)
	}
	oldLeft, err = hunkCount(fields[1][1:])
	if err != nil {
		return 0, 0, badPatch("malformed hunk header %q", line)
	}
	newLeft, err = hunkCount(fields[2][1:])
	if err != nil {
		return 0, 0, badPatch("malformed hunk header %q", line)
	}
	return oldLeft, newLeft, nil
}

func hunkCount(s string) (int, error) {
	if _, count, ok := strings.Cut(s, ","); ok {
		s = count
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

// headerPath returns the path component of a ---/+++ line, dropping any
// timestamp after a tab.
func headerPath(line string) string {
	rest := strings.TrimSpace(line[4:])
	if i := strings.IndexByte(rest, '\t'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func checkPatchPaths(oldPath, newPath string) error {
	if oldPath == "/dev/null" && newPath == "/dev/null" {
		return badPatch("a file header pair names /dev/null on both sides")
	}
	if oldPath != "/dev/null" && !strings.HasPrefix(oldPath, "a/") {
		return badPatch("%q has no a/ path prefix; git diff output is required because patch -p1 needs a prefix to strip", oldPath)
	}
	if newPath != "/dev/null" && !strings.HasPrefix(newPath, "b/") {
		return badPatch("%q has no b/ path prefix; git diff output is required because patch -p1 needs a prefix to strip", newPath)
	}
	for _, p := range []string{oldPath, newPath} {
		if p == "/dev/null" {
			continue
		}
		if filepath.IsAbs(p) {
			return badPatch("absolute path %q", p)
		}
		for _, part := range strings.Split(p, "/") {
			if part == "" {
				return badPatch("path %q has an empty component", p)
			}
			if part == ".." {
				return badPatch("path %q escapes the scratch workspace", p)
			}
		}
	}
	return nil
}

func badPatch(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadPatch, fmt.Sprintf(format, args...))
}

func hintBlock(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 2000 {
		s = "..." + s[len(s)-2000:]
	}
	return "\n" + s
}

// copyTree copies src into dst, skipping the pipeline's own state (.pocgate) and
// version-control metadata (.git). Verification renders the target from its
// source tree; it never needs history, and copying it could be expensive.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if tree.SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(dst, rel))
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Set the mode explicitly: os.WriteFile's creation mode is filtered by
		// the process umask, which would change the digest of a copied tree.
		dstPath := filepath.Join(dst, rel)
		if err := os.WriteFile(dstPath, data, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(dstPath, info.Mode().Perm())
	})
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func short(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}
