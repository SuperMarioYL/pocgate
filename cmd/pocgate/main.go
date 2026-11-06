// Command pocgate is the closure gate for machine-written patches: it decides
// whether a patch actually closed a vulnerability by replaying PoCs before and
// after the fix.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/SuperMarioYL/pocgate/internal/demo"
	"github.com/SuperMarioYL/pocgate/internal/evidence"
	"github.com/SuperMarioYL/pocgate/internal/oracle"
	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/verdict"
)

// version is the CLI version without a leading "v". The repo-root VERSION file
// is the single source the release tooling tags v<version> from; release builds
// may also stamp this variable with -ldflags "-X main.version=<version>".
var version = "0.1.0"

// Exit codes.
//
// Verdict exit codes are owned by internal/verdict and are confined to 0-3:
//
//	0  CLOSED             the patch closed the vulnerability
//	1  STILL_VULNERABLE   at least one PoC still fires after the patch
//	2  REGRESSION_BROKEN  the regression set gained new failures
//	3  INCONCLUSIVE       the pre/post observation could not prove closure
//
// CLI failures never reuse that range; they follow sysexits and stay outside
// 0-3 so a gate script can tell "the patch is bad" from "the tool misbehaved":
//
//	64  usage error    bad command line, unknown flag, or a patch that cannot apply
//	70  internal error a genuine tool failure, not the operator's input
//	78  config error   bad, missing, or unreadable pocgate.yaml
//
// Help and version are plain successes and exit 0, the same code a CLOSED
// verdict carries.
const (
	exitOK = 0

	// exitInconclusive is the verdict code for INCONCLUSIVE; internal/verdict
	// owns the full 0-3 mapping.
	exitInconclusive = 3

	exitUsage    = 64
	exitInternal = 70
	exitConfig   = 78
)

// command documents one entry of the CLI surface for the help listing.
type command struct {
	name    string
	summary string
}

var commands = []command{
	{"init", "scaffold pocgate.yaml in the target repository"},
	{"baseline", "build the target, run every PoC, and record the vulnerable baseline"},
	{"verify", "apply a patch in a scratch copy and decide the closure verdict"},
	{"demo", "run the bundled fixture from red to green"},
	{"attest", "verify signed evidence (attest verify --pubkey <key> <evidence.json>)"},
	{"doctor", "check patch, build tools, ports, and the local signing key"},
}

func main() {
	// SIGINT/SIGTERM cancels the pipeline's context, so the deferred service
	// Stop runs and kills the target's process group instead of leaving it and
	// the PoC children alive holding the port.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a full argument list and returns the process exit code. It is
// split out of main so the CLI surface stays testable without spawning a process.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return exitOK
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "pocgate %s\n", version)
		return exitOK
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "baseline":
		return runBaseline(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	case "demo":
		return runDemo(ctx, args[1:], stdout, stderr)
	case "attest":
		return runAttest(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "pocgate: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return exitUsage
	}
}

func runBaseline(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("baseline", "pocgate baseline [--spec path]", stderr)
	specPath := fs.String("spec", "pocgate.yaml", "path to the target's pocgate.yaml")
	if stop, code := parseFlags(fs, args); stop {
		return code
	}

	baseline, err := oracle.Capture(ctx, *specPath, oracle.Options{Version: version})
	if baseline != nil {
		baseline.Report(stdout)
	}
	switch {
	case err == nil:
		fmt.Fprintf(stdout, "baseline written: %s\n", baseline.Path)
		return exitOK
	case errors.Is(err, oracle.ErrInconclusive):
		fmt.Fprintf(stderr, "pocgate baseline: INCONCLUSIVE: %v\nrefusing to write baseline\n", err)
		return exitInconclusive
	case errors.Is(err, spec.ErrConfig):
		fmt.Fprintf(stderr, "pocgate baseline: %v\n", err)
		return exitConfig
	default:
		fmt.Fprintf(stderr, "pocgate baseline: %v\n", err)
		return exitInternal
	}
}

// runVerify applies a patch in a scratch copy of the target, observes the three
// closure legs, writes signed evidence, and exits with the verdict's code.
//
// --fail-on turns the verdict into a plain CI gate: exit 1 when the verdict's
// closure risk is at or above the named threshold, 0 below it. The risk order
// is CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE, so every
// threshold fails an INCONCLUSIVE verdict: a gate that could not observe the
// target must never be green. Without --fail-on the exit code is the verdict
// itself (0-3), so a script can tell which of the four states it got.
func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", "pocgate verify --patch <diff> [--spec path] [--json] [--fail-on <verdict>]", stderr)
	specPath := fs.String("spec", "pocgate.yaml", "path to the target's pocgate.yaml")
	patchPath := fs.String("patch", "", "git-style diff to verify (required)")
	asJSON := fs.Bool("json", false, "print the result as canonical JSON on stdout")
	failOn := fs.String("fail-on", "", "exit 1 when closure risk is at least <verdict>; risk order is CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE, so any threshold fails an unobservable run")
	if stop, code := parseFlags(fs, args); stop {
		return code
	}
	if *patchPath == "" {
		fmt.Fprintln(stderr, "pocgate verify: --patch <diff> is required")
		return exitUsage
	}
	if *failOn != "" {
		v, err := verdict.Parse(*failOn)
		if err != nil || v == verdict.Closed {
			fmt.Fprintf(stderr, "pocgate verify: invalid --fail-on %q: want INCONCLUSIVE, REGRESSION_BROKEN, or STILL_VULNERABLE\n", *failOn)
			return exitUsage
		}
	}

	sp, err := spec.Load(*specPath)
	if err != nil {
		fmt.Fprintf(stderr, "pocgate verify: %v\n", err)
		return exitConfig
	}

	doc, err := verdict.Run(ctx, verdict.Request{Spec: sp, PatchPath: *patchPath, Version: version})
	if err != nil {
		if errors.Is(err, verdict.ErrBadPatch) {
			fmt.Fprintf(stderr, "pocgate verify: invalid patch: %v\n", err)
			// A bad patch still leaves the gate without evidence, so --json must
			// produce the documented error object instead of empty stdout.
			if *asJSON {
				printJSONError(stdout, string(verdict.Inconclusive), err.Error())
			}
			return exitUsage
		}
		fmt.Fprintf(stderr, "pocgate verify: %v\n", err)
		if *asJSON {
			printJSONError(stdout, string(verdict.Inconclusive), err.Error())
		}
		if errors.Is(err, verdict.ErrInconclusive) {
			return verdictExit(verdict.Inconclusive, *failOn)
		}
		return exitInternal
	}

	path := filepath.Join(sp.Dir, ".pocgate", "evidence", "latest.json")
	if err := evidence.Write(path, doc); err != nil {
		fmt.Fprintf(stderr, "pocgate verify: write evidence: %v\n", err)
		return exitInternal
	}

	if *asJSON {
		data, err := evidence.Bytes(doc)
		if err != nil {
			fmt.Fprintf(stderr, "pocgate verify: encode evidence: %v\n", err)
			return exitInternal
		}
		fmt.Fprintf(stdout, "%s\n", data)
	} else {
		reportVerify(stdout, doc, path)
	}
	return verdictExit(verdict.Verdict(doc.Verdict), *failOn)
}

// reportVerify is the human-readable form of one gate run.
func reportVerify(w io.Writer, d *evidence.Document, path string) {
	fmt.Fprintf(w, "target: %s  patch: %s\n", d.Target.Name, shortSHA(d.Target.PatchSHA256))
	for _, o := range d.Oracles {
		fmt.Fprintf(w, "%s: pre FIRED %d/%d (exit %d) → post FIRED %d/%d (exit %d)\n",
			o.ID, o.Pre.Fired, o.Repeats, o.Pre.Exit, o.Post.Fired, o.Repeats, o.Post.Exit)
	}
	fmt.Fprintf(w, "regression: %s, new failures: %d\n", d.Regression.Parser, len(d.Regression.NewFailures))
	for _, id := range d.Regression.NewFailures {
		fmt.Fprintf(w, "  new failure: %s\n", id)
	}
	fmt.Fprintf(w, "verdict: %s\n", d.Verdict)
	fmt.Fprintf(w, "evidence: %s\n", path)
	fmt.Fprintf(w, "  digest: %s\n", d.Digest)
}

// printJSONError is the --json shape when the gate has no evidence document to
// print, so CI can read the outcome without scraping stderr.
func printJSONError(w io.Writer, v, message string) {
	data, err := json.Marshal(struct {
		Verdict string `json:"verdict"`
		Error   string `json:"error"`
	}{Verdict: v, Error: message})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "%s\n", data)
}

// verdictExit maps a verdict to the process status. Without --fail-on it is the
// verdict itself; with it, a plain 0/1 gate at the named closure-risk threshold.
func verdictExit(v verdict.Verdict, failOn string) int {
	if failOn == "" {
		return v.ExitCode()
	}
	threshold, err := verdict.Parse(failOn)
	if err != nil || threshold == verdict.Closed {
		return exitUsage
	}
	if v.AtLeastRisk(threshold) {
		return 1
	}
	return 0
}

func shortSHA(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}

func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("demo", "pocgate demo [--evidence path]", stderr)
	evidencePath := fs.String("evidence", "", "where to write the signed evidence (default .pocgate/evidence/latest.json)")
	if stop, code := parseFlags(fs, args); stop {
		return code
	}
	err := demo.Run(ctx, demo.Options{Out: stdout, Version: version, EvidencePath: *evidencePath})
	if err != nil {
		fmt.Fprintf(stderr, "pocgate demo: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func runAttest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printAttestUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		printAttestUsage(stdout)
		return exitOK
	case "verify":
		return runAttestVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "pocgate attest: unknown subcommand %q\n\n", args[0])
		printAttestUsage(stderr)
		return exitUsage
	}
}

func runAttestVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("attest verify", "pocgate attest verify --pubkey <key> <evidence.json>", stderr)
	pubkey := fs.String("pubkey", "", "public key file of the expected signer (required)")
	positional, stop, code := parseFlagsAnywhere(fs, args)
	if stop {
		return code
	}
	if len(positional) != 1 || *pubkey == "" {
		fmt.Fprintln(stderr, "pocgate attest verify: --pubkey <key> is required; a key stored next to the evidence only proves self-consistency")
		printAttestUsage(stderr)
		return exitUsage
	}

	path := positional[0]
	doc, err := evidence.Verify(path, *pubkey)
	if err != nil {
		fmt.Fprintf(stderr, "pocgate attest verify: FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "attest verify: OK\n")
	fmt.Fprintf(stdout, "  file:    %s\n", path)
	fmt.Fprintf(stdout, "  pubkey:  %s\n", *pubkey)
	fmt.Fprintf(stdout, "  verdict: %s\n", doc.Verdict)
	fmt.Fprintf(stdout, "  digest:  %s\n", doc.Digest)
	return exitOK
}

// parseFlagsAnywhere parses flags that may appear before or after the command's
// positional arguments, so "attest verify evidence.json --pubkey key" works as
// well as the canonical order. The standard flag package stops at the first
// non-flag argument, hence the loop.
func parseFlagsAnywhere(fs *flag.FlagSet, args []string) (positional []string, stop bool, code int) {
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, true, exitOK
			}
			return nil, true, exitUsage
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, false, exitOK
		}
		positional = append(positional, rest[0])
		args = rest[1:]
		if len(args) == 0 {
			return positional, false, exitOK
		}
	}
}

func newFlagSet(name, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "Usage:\n  %s\n", usage) }
	return fs
}

// parseFlags reports whether the caller should return early (help was requested
// or parsing failed) and with which exit code.
func parseFlags(fs *flag.FlagSet, args []string) (stop bool, code int) {
	err := fs.Parse(args)
	if err == nil {
		return false, exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return true, exitOK
	}
	return true, exitUsage
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `pocgate decides whether a patch actually closed a vulnerability: every PoC must
fire on the vulnerable build, none may fire after the patch, and the regression
set must gain no new failures.

Usage:
  pocgate <command> [flags]

Commands:
`)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
  help      show this help
  version   print the version

Exit status:
  0  CLOSED, or a plain success such as help and version
  1  STILL_VULNERABLE   2  REGRESSION_BROKEN   3  INCONCLUSIVE
  64 usage error        70 internal error       78 config error

Run "pocgate <command> -h" for the usage of a command.
`)
}

func printAttestUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  pocgate attest verify --pubkey <key> <evidence.json>

Recompute the canonical digest of an evidence file and check its signature
against the public key named by --pubkey. The key is a required trust anchor:
a .pub file sitting next to the evidence is not used, because whoever can
rewrite the evidence can rewrite that key too. Obtain the expected key out of
band and pass it explicitly. Verification is offline.

Exit status:
  0  the evidence verifies against the given key
  1  verification failed: a byte changed, or the digest/signature does not hold
  64 usage error: --pubkey or the evidence path is missing
`)
}
