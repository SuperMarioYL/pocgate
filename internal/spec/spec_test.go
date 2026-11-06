package spec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// load writes body and a dummy PoC into a fresh directory and loads the spec.
func load(t *testing.T, body string) (*Spec, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "poc.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pocgate.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const validSpec = `target:
  name: shop
  build: go build ./...
  service:
    cmd: ./shop
    port: 18081
oracles:
  - id: authbypass
    poc: poc.sh
regression:
  cmd: go test ./...
labels:
  cve: CVE-2026-00000
`

func TestLoadAppliesDefaults(t *testing.T) {
	s, err := load(t, validSpec)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Dir == "" || !filepath.IsAbs(s.Dir) {
		t.Errorf("Dir = %q, want absolute spec directory", s.Dir)
	}
	if got := s.Oracles[0].Repeats; got != DefaultRepeats {
		t.Errorf("repeats = %d, want %d", got, DefaultRepeats)
	}
	if got := s.Oracles[0].FiredWhen.ExitCode(); got != 0 {
		t.Errorf("fired_when.exit = %d, want 0", got)
	}
	if got := s.Target.Service.ReadyTimeout(); got != DefaultReadyTimeoutSec*time.Second {
		t.Errorf("ready timeout = %s, want %ds", got, DefaultReadyTimeoutSec)
	}
	if got := s.Target.BuildTimeout(); got != DefaultBuildTimeoutSec*time.Second {
		t.Errorf("build timeout = %s, want %ds", got, DefaultBuildTimeoutSec)
	}
	if got := s.Oracles[0].Timeout(); got != DefaultOracleTimeoutSec*time.Second {
		t.Errorf("oracle timeout = %s, want %ds", got, DefaultOracleTimeoutSec)
	}
	if got := s.Regression.Parser; got != ParserExitCode {
		t.Errorf("parser = %q, want %q", got, ParserExitCode)
	}
	if got := s.Oracles[0].PoCFile(); got != filepath.Join(s.Dir, "poc.sh") {
		t.Errorf("PoCFile = %q, want absolute path under %q", got, s.Dir)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"top level": {
			body: validSpec + "extra: 1\n",
			want: "field extra not found",
		},
		"nested": {
			body: `target:
  name: shop
  build: go build ./...
  bogus: true
oracles:
  - id: authbypass
    poc: poc.sh
`,
			want: "field bogus not found",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.body)
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadValidation(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"empty file": {
			body: "",
			want: "spec is empty",
		},
		"two documents": {
			body: validSpec + "---\ntarget: {}\n",
			want: "only one YAML document",
		},
		"missing target name": {
			body: `target:
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
`,
			want: "target.name",
		},
		"missing build": {
			body: `target:
  name: shop
oracles:
  - id: a
    poc: poc.sh
`,
			want: "target.build",
		},
		"no oracles": {
			body: `target:
  name: shop
  build: go build ./...
`,
			want: "oracles: at least one PoC",
		},
		"empty oracle id": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - poc: poc.sh
`,
			want: "oracles[0].id",
		},
		"duplicate oracle id": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
  - id: a
    poc: poc.sh
`,
			want: "duplicate id",
		},
		"missing PoC file": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: nope.sh
`,
			want: "oracles[0].poc",
		},
		"negative repeats": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    repeats: -1
`,
			want: "repeats: must be at least 1",
		},
		"negative oracle timeout": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    timeout_sec: -5
`,
			want: "timeout_sec: must be at least 1",
		},
		"negative build timeout": {
			body: `target:
  name: shop
  build: go build ./...
  build_timeout_sec: -5
oracles:
  - id: a
    poc: poc.sh
`,
			want: "build_timeout_sec: must be at least 1",
		},
		"invalid stdout regex": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      stdout: "("
`,
			want: "invalid regular expression",
		},
		"exit code out of range": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      exit: 300
`,
			want: "between 0 and 255",
		},
		"silent exit out of range": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      silent_exit: 300
`,
			want: "silent_exit: must be between 0 and 255",
		},
		"silent exit equal to the fire exit": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      exit: 1
      silent_exit: 1
`,
			want: "silent_exit: must differ",
		},
		"unknown parser": {
			body: `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
regression:
  cmd: go test ./...
  parser: tap
`,
			want: "regression.parser",
		},
		"service port without command": {
			body: `target:
  name: shop
  build: go build ./...
  service:
    port: 18081
oracles:
  - id: a
    poc: poc.sh
`,
			want: "requires target.service.cmd",
		},
		"service command without port": {
			body: `target:
  name: shop
  build: go build ./...
  service:
    cmd: ./shop
oracles:
  - id: a
    poc: poc.sh
`,
			want: "not a valid TCP port",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.body)
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadWrapsConfigErrors(t *testing.T) {
	_, err := load(t, "target:\n  name: shop\n")
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("Load error = %v, want it to wrap ErrConfig", err)
	}
}

func TestFiredWhen(t *testing.T) {
	s, err := load(t, `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      exit: 2
      stdout: BYPASS
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := s.Oracles[0].FiredWhen
	if !f.Fires(2, []byte("admin session BYPASS\n")) {
		t.Error("run matching exit and stdout did not fire")
	}
	if f.Fires(0, []byte("admin session BYPASS\n")) {
		t.Error("run with the wrong exit code fired")
	}
	if f.Fires(2, []byte("blocked")) {
		t.Error("run without the stdout pattern fired")
	}
}

// TestOutcomeIsTriState pins the three-way classification: only the declared
// silent exit means silence; every other non-fire exit is unobserved.
func TestOutcomeIsTriState(t *testing.T) {
	s, err := load(t, `target:
  name: shop
  build: go build ./...
oracles:
  - id: a
    poc: poc.sh
    fired_when:
      exit: 0
      silent_exit: 1
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := s.Oracles[0].FiredWhen

	tests := []struct {
		name   string
		exit   int
		stdout string
		want   Outcome
	}{
		{"fire exit", 0, "", Fired},
		{"declared silent exit", 1, "", Silent},
		{"crash", 3, "", Unobserved},
		{"transport failure", 2, "", Unobserved},
		{"fire exit from a wrong code", 127, "", Unobserved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.Outcome(tt.exit, []byte(tt.stdout)); got != tt.want {
				t.Fatalf("Outcome(%d) = %v, want %v", tt.exit, got, tt.want)
			}
		})
	}
}
