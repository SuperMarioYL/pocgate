package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// starterSpec is what "pocgate init" writes. It is a commented walk through the
// four blocks a gate needs, with the values that most often get a first run
// wrong called out next to them.
//
// The file is deliberately not runnable as written: it names a PoC that does not
// exist yet, because writing a PoC that proves a real flaw is the operator's
// work, not scaffolding. "pocgate baseline" reports the missing file precisely.
const starterSpec = `# pocgate.yaml — what to build, which PoCs prove the flaw, and how to check
# for regressions. Every relative path resolves against this file's directory,
# and every command runs from it.
#
# The verdict is a three-leg conjunction, so all three blocks carry weight:
#
#   1. every PoC below must fire on every run of the vulnerable build,
#   2. no PoC may fire on any run after the patch,
#   3. the regression command must gain no new failure.
#
# A PoC that does not fire before the patch makes the verdict INCONCLUSIVE
# rather than CLOSED: pocgate will not call a patch a fix when it cannot show
# the flaw reproduced in the first place.

target:
  name: my-service
  # Run after a fresh checkout. Exit 0 means the build succeeded.
  build: go build ./...
  build_timeout_sec: 300

  # Delete this block when the PoCs exercise the build themselves (a CLI, a
  # test harness). Keep it when they speak HTTP: pocgate starts the command,
  # waits for the TCP port, and stops the whole process group afterwards.
  service:
    cmd: ./bin/my-service
    port: 8080
    ready_timeout_sec: 20
    env:
      LISTEN_ADDR: 127.0.0.1:8080

oracles:
  # One entry per flaw. The id appears in every report and in the evidence.
  - id: authbypass
    poc: pocs/authbypass.sh
    # Each side runs this many times; one flaky run is not a verdict.
    repeats: 3
    timeout_sec: 60
    # env:
    #   POCGATE_TARGET_URL: http://127.0.0.1:8080
    fired_when:
      # exit is the code that means "the flaw reproduced" (default 0).
      exit: 0
      # silent_exit is the code the PoC reserves for "the target answered and
      # the flaw is gone". Declaring it is what lets a silent run support a
      # closure: any other exit stays UNOBSERVED and yields INCONCLUSIVE.
      silent_exit: 1
      # Optional: the run must also print this regular expression.
      # stdout: 'ADMIN-ACTION-ALLOWED'

regression:
  # The failure set before and after the patch. exit_code treats the whole
  # command as one check; junit_xml reads the report from stdout.
  cmd: go test ./...
  parser: exit_code

labels:
  # Recorded verbatim. pocgate never infers a mapping.
  cve: CVE-2026-00000
  # technique: T1078
`

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", "pocgate init [--force]", stderr)
	force := fs.Bool("force", false, "overwrite an existing pocgate.yaml")
	if stop, code := parseFlags(fs, args); stop {
		return code
	}

	const path = "pocgate.yaml"
	if !*force {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(stderr, "pocgate init: %s already exists; pass --force to overwrite it\n", path)
			return exitUsage
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "pocgate init: %v\n", err)
			return exitInternal
		}
	}
	if err := os.WriteFile(path, []byte(starterSpec), 0o644); err != nil {
		fmt.Fprintf(stderr, "pocgate init: %v\n", err)
		return exitInternal
	}

	fmt.Fprintf(stdout, "wrote %s\n\n", path)
	fmt.Fprint(stdout, `next:
  1. put one PoC per flaw under pocs/ and make it exit 0 when the flaw
     reproduces, 1 when the target answers and the flaw is gone, and any
     other code when it could not tell (do not use curl -f: it hides a 401
     behind the same non-zero exit a broken target produces)
  2. point target, oracles, and regression at your own commands
  3. pocgate baseline     record the vulnerable build
  4. pocgate verify --patch fix.diff
`)
	return exitOK
}
