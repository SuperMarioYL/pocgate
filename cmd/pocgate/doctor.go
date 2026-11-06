package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/SuperMarioYL/pocgate/internal/evidence"
	"github.com/SuperMarioYL/pocgate/internal/exec"
	"github.com/SuperMarioYL/pocgate/internal/spec"
)

// Check statuses. A failing check blocks a gate run; a warning does not, and
// every warning names what is missing for which part of the workflow.
const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"
)

// probeBudget bounds each shell probe, so doctor keeps its sub-10-second
// promise even when a PATH entry hangs.
const probeBudget = 5 * time.Second

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Version string        `json:"version"`
	OS      string        `json:"os"`
	Arch    string        `json:"arch"`
	OK      bool          `json:"ok"`
	Checks  []doctorCheck `json:"checks"`
}

// runDoctor reports whether this machine can run the gate: the shell and patch
// the pipeline itself needs, the tools Go targets and the bundled demo use, the
// spec's validity, the service port, and the local signing key.
//
// A missing spec is a warning, not a failure: the plan's happy path runs doctor
// before init, so the first check must not demand a file the operator has not
// written yet.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("doctor", "pocgate doctor [--spec path] [--json]", stderr)
	specPath := fs.String("spec", "pocgate.yaml", "spec to validate")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if stop, code := parseFlags(fs, args); stop {
		return code
	}

	report, code := diagnose(ctx, *specPath)
	if *asJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "pocgate doctor: %v\n", err)
			return exitInternal
		}
		fmt.Fprintf(stdout, "%s\n", data)
		return code
	}
	writeDoctorReport(stdout, report)
	return code
}

// diagnose collects the checks and maps the worst finding to an exit status.
// A bad spec is a configuration error, an unusable environment an internal one;
// the spec wins because the operator has to fix it first either way.
func diagnose(ctx context.Context, specPath string) (doctorReport, int) {
	report := doctorReport{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	add := func(name, status, detail string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	// The pipeline runs every spec command through sh and applies patches with
	// patch -p1, so these two are the only fatal tool gaps.
	envFailed := false
	if path, ok := locate(ctx, "sh"); ok {
		add("shell", statusOK, path)
	} else {
		add("shell", statusFail, "not found on PATH; pocgate runs spec commands through sh")
		envFailed = true
	}
	if path, ok := locate(ctx, "patch"); ok {
		add("patch", statusOK, path)
	} else {
		add("patch", statusFail, "not found on PATH; pocgate verify applies diffs with patch -p1")
		envFailed = true
	}

	if _, ok := locate(ctx, "go"); ok {
		add("go", statusOK, goVersion(ctx))
	} else {
		add("go", statusWarn, "not found on PATH; Go targets and the bundled demo need it")
	}
	if path, ok := locate(ctx, "curl"); ok {
		add("curl", statusOK, path)
	} else {
		add("curl", statusWarn, "not found on PATH; the bundled PoCs probe HTTP with it")
	}

	specFailed := false
	sp, specStatus := checkSpec(specPath)
	add("spec", specStatus.status, specStatus.detail)
	specFailed = specStatus.status == statusFail

	port := 0
	if sp != nil {
		port = sp.Target.Service.Port
	}
	switch {
	case port == 0:
		add("port", statusOK, "no service declared; the PoCs exercise the build")
	case portFree(port):
		add("port", statusOK, fmt.Sprintf("127.0.0.1:%d is free", port))
	default:
		add("port", statusFail, fmt.Sprintf("127.0.0.1:%d is already in use", port))
		envFailed = true
	}

	keyPath, present, keyErr := evidence.LocalKeyStatus()
	switch {
	case keyErr != nil:
		add("signing key", statusFail, fmt.Sprintf("%s: %v", keyPath, keyErr))
		envFailed = true
	case present:
		add("signing key", statusOK, keyPath)
	default:
		add("signing key", statusWarn, keyPath+" does not exist yet; the first signed evidence creates it")
	}

	report.OK = true
	for _, c := range report.Checks {
		if c.Status == statusFail {
			report.OK = false
		}
	}
	switch {
	case specFailed:
		return report, exitConfig
	case envFailed:
		return report, exitInternal
	default:
		return report, exitOK
	}
}

// specCheck is the spec entry's result. The loaded spec is returned separately
// because the port check needs it too.
type specCheck struct {
	status string
	detail string
}

func checkSpec(path string) (*spec.Spec, specCheck) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, specCheck{
				status: statusWarn,
				detail: fmt.Sprintf("no %s here; pocgate init writes a commented starter", path),
			}
		}
		return nil, specCheck{status: statusFail, detail: err.Error()}
	}
	sp, err := spec.Load(path)
	if err != nil {
		return nil, specCheck{status: statusFail, detail: err.Error()}
	}
	ids := make([]string, 0, len(sp.Oracles))
	repeats := sp.Oracles[0].Repeats
	for _, o := range sp.Oracles {
		ids = append(ids, o.ID)
	}
	return sp, specCheck{
		status: statusOK,
		detail: fmt.Sprintf("%s: %s (%s), %d runs per side, regression %s",
			path, count(len(sp.Oracles), "oracle"), strings.Join(ids, ", "), repeats, sp.Regression.Parser),
	}
}

// locate resolves a tool through the shell, so the check uses the same PATH the
// pipeline's commands will use.
func locate(ctx context.Context, name string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, probeBudget)
	defer cancel()
	res, err := exec.RunShell(cctx, "", "command -v "+name, nil)
	if err != nil || res.ExitCode != 0 {
		return "", false
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), "\n")
	return line, line != ""
}

// goVersion reports the toolchain string when it can be read, and the resolved
// path otherwise. A version probe that fails is not a failed check: the binary
// was found, which is what the gate needs.
func goVersion(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(ctx, probeBudget)
	defer cancel()
	res, err := exec.RunShell(cctx, "", "go version", nil)
	if err != nil || res.ExitCode != 0 {
		return "found"
	}
	if out := strings.TrimSpace(string(res.Stdout)); out != "" {
		return out
	}
	return "found"
}

// portFree reports whether the service can bind the port. Listening is the only
// authoritative test: a dial cannot tell "nothing is listening" from "something
// is listening but refuses", and the gate needs the port itself.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func writeDoctorReport(w io.Writer, report doctorReport) {
	var ok, warnings, failures int
	fmt.Fprintf(w, "pocgate %s doctor (%s/%s)\n\n", report.Version, report.OS, report.Arch)
	for _, c := range report.Checks {
		switch c.Status {
		case statusOK:
			ok++
		case statusWarn:
			warnings++
		default:
			failures++
		}
		fmt.Fprintf(w, "  [%-4s] %-11s %s\n", c.Status, c.Name, c.Detail)
	}
	fmt.Fprintf(w, "\ndoctor: %d ok, %s, %s\n", ok, count(warnings, "warning"), count(failures, "failure"))
	switch {
	case failures > 0:
		fmt.Fprintln(w, "blocking: fix the entries marked [fail] before running baseline")
	case warnings > 0:
		fmt.Fprintln(w, "nothing blocking")
	default:
		fmt.Fprintln(w, "ready: pocgate demo needs no further setup")
	}
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
