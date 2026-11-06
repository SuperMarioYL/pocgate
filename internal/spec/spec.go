// Package spec parses and validates pocgate.yaml. It is the only owner of the
// spec schema: oracle, regress, verdict, and the CLI consume the types defined
// here instead of re-reading the file.
package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults for optional fields. They are named so the CLI and the fixture can
// refer to the same numbers the parser applies.
const (
	DefaultRepeats          = 3
	DefaultReadyTimeoutSec  = 20
	DefaultOracleTimeoutSec = 60
	DefaultBuildTimeoutSec  = 300
)

// ErrConfig marks a spec or configuration problem: the operator must fix the
// input before the gate can observe anything. Callers map it to the
// configuration exit status instead of the internal-failure one.
var ErrConfig = errors.New("configuration error")

// Regression parsers accepted by the spec.
const (
	ParserExitCode = "exit_code"
	ParserJUnitXML = "junit_xml"
)

// Spec is one pocgate.yaml document. Dir is the absolute directory of the file:
// every relative path in the document resolves against it, and every target
// command runs there.
type Spec struct {
	Target     Target     `yaml:"target"`
	Oracles    []Oracle   `yaml:"oracles"`
	Regression Regression `yaml:"regression"`
	Labels     Labels     `yaml:"labels"`

	Dir  string `yaml:"-"`
	Path string `yaml:"-"`
}

// Target describes what to build and, optionally, the service the PoCs probe.
// Without a service the PoCs are expected to exercise the build themselves.
type Target struct {
	Name            string  `yaml:"name"`
	Build           string  `yaml:"build"`
	BuildTimeoutSec int     `yaml:"build_timeout_sec"`
	Service         Service `yaml:"service"`
}

// BuildTimeout is the normalized budget for the build command.
func (t Target) BuildTimeout() time.Duration {
	return time.Duration(t.BuildTimeoutSec) * time.Second
}

// Service is a long-running process started before the PoCs run. Readiness is
// a TCP connect to Port on 127.0.0.1, polled until ReadyTimeoutSec elapses.
type Service struct {
	Cmd             string            `yaml:"cmd"`
	Port            int               `yaml:"port"`
	ReadyTimeoutSec int               `yaml:"ready_timeout_sec"`
	Env             map[string]string `yaml:"env"`
}

// Enabled reports whether the spec declares a service to run.
func (s Service) Enabled() bool { return s.Cmd != "" }

// ReadyTimeout is the normalized readiness budget.
func (s Service) ReadyTimeout() time.Duration {
	return time.Duration(s.ReadyTimeoutSec) * time.Second
}

// Oracle is one proof-of-concept whose firing proves the target is vulnerable.
type Oracle struct {
	ID         string            `yaml:"id"`
	PoC        string            `yaml:"poc"`
	Repeats    int               `yaml:"repeats"`
	TimeoutSec int               `yaml:"timeout_sec"`
	Env        map[string]string `yaml:"env"`
	FiredWhen  FiredWhen         `yaml:"fired_when"`

	pocFile string
}

// Timeout is the normalized budget for all of one oracle's runs, so a hung PoC
// cannot block the gate forever.
func (o Oracle) Timeout() time.Duration {
	return time.Duration(o.TimeoutSec) * time.Second
}

// PoCFile is the absolute path of the PoC script, resolved against the spec
// directory when the spec is loaded.
func (o Oracle) PoCFile() string { return o.pocFile }

// FiredWhen is the condition that classifies one run. The exit code is the
// primary signal; the optional stdout regex must also match for a fire.
//
// A run has three outcomes, not two:
//
//   - fired: the exit code is Exit (default 0) and stdout matches;
//   - silent: the exit code is SilentExit, the code a PoC reserves for a
//     definite, non-vulnerable response from a working target;
//   - unobserved: any other exit. A crash, a 500, or an unreachable port also
//     exits non-zero, so silence must never be inferred from an undeclared
//     exit: that would turn a broken build into a closure claim.
type FiredWhen struct {
	Exit       *int   `yaml:"exit"`
	SilentExit *int   `yaml:"silent_exit"`
	Stdout     string `yaml:"stdout"`

	stdout *regexp.Regexp
}

// ExitCode is the exit code a run must return to be considered fired. It
// defaults to 0, which is the PoC convention: a script exits 0 when the flaw
// reproduces.
func (f FiredWhen) ExitCode() int {
	if f.Exit == nil {
		return 0
	}
	return *f.Exit
}

// Outcome is how one run's exit and output are classified.
type Outcome int

const (
	// Unobserved means the run's exit is neither the fire code nor the
	// declared silent code, so the run proves nothing either way.
	Unobserved Outcome = iota
	// Fired means the run reproduced the vulnerability.
	Fired
	// Silent means the run completed and observed a definite, non-vulnerable
	// response. Only a declared silent exit can support a closure claim.
	Silent
)

// Outcome classifies one finished run.
func (f FiredWhen) Outcome(exit int, stdout []byte) Outcome {
	if exit == f.ExitCode() {
		if f.stdout == nil || f.stdout.Match(stdout) {
			return Fired
		}
		return Unobserved
	}
	if f.SilentExit != nil && exit == *f.SilentExit {
		return Silent
	}
	return Unobserved
}

// Fires reports whether one run reproduced the vulnerability. It is the Fired
// case of Outcome, kept for callers that only ask that question.
func (f FiredWhen) Fires(exit int, stdout []byte) bool {
	return f.Outcome(exit, stdout) == Fired
}

// Regression is the command whose failure set must not grow after the patch.
// The baseline stage records it but does not run it.
type Regression struct {
	Cmd    string `yaml:"cmd"`
	Parser string `yaml:"parser"`
}

// Labels are operator-supplied metadata. pocgate records them and never infers
// a mapping.
type Labels struct {
	CVE       string `yaml:"cve"`
	Technique string `yaml:"technique"`
}

// Load reads, strictly decodes, normalizes, and validates a spec file. Unknown
// fields are rejected so a typo cannot silently disable a check. Every failure
// is something the operator must fix, so it wraps ErrConfig.
func Load(path string) (*Spec, error) {
	s, err := loadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return s, nil
}

func loadFile(path string) (*Spec, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: spec is empty", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: only one YAML document is allowed", path)
	}

	s.Path = abs
	s.Dir = filepath.Dir(abs)
	if err := s.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// normalize applies defaults and compiles the derived values a loaded spec
// needs. Validation errors that depend on the raw values stay in validate.
func (s *Spec) normalize() error {
	if s.Target.BuildTimeoutSec == 0 {
		s.Target.BuildTimeoutSec = DefaultBuildTimeoutSec
	}
	if s.Target.Service.Enabled() && s.Target.Service.ReadyTimeoutSec == 0 {
		s.Target.Service.ReadyTimeoutSec = DefaultReadyTimeoutSec
	}
	for i := range s.Oracles {
		o := &s.Oracles[i]
		if o.Repeats == 0 {
			o.Repeats = DefaultRepeats
		}
		if o.TimeoutSec == 0 {
			o.TimeoutSec = DefaultOracleTimeoutSec
		}
		if o.FiredWhen.Stdout != "" {
			re, err := regexp.Compile(o.FiredWhen.Stdout)
			if err != nil {
				return fmt.Errorf("oracles[%d].fired_when.stdout: invalid regular expression: %w", i, err)
			}
			o.FiredWhen.stdout = re
		}
		if o.PoC != "" && !filepath.IsAbs(o.PoC) {
			o.pocFile = filepath.Join(s.Dir, o.PoC)
		} else {
			o.pocFile = o.PoC
		}
	}
	if s.Regression.Cmd != "" && s.Regression.Parser == "" {
		s.Regression.Parser = ParserExitCode
	}
	return nil
}

func (s *Spec) validate() error {
	if s.Target.Name == "" {
		return errors.New("target.name: must not be empty")
	}
	if s.Target.Build == "" {
		return errors.New("target.build: must not be empty")
	}
	if s.Target.BuildTimeoutSec < 1 {
		return errors.New("target.build_timeout_sec: must be at least 1")
	}
	if err := validateService(s.Target.Service); err != nil {
		return err
	}

	if len(s.Oracles) == 0 {
		return errors.New("oracles: at least one PoC is required")
	}
	seen := make(map[string]bool, len(s.Oracles))
	for i, o := range s.Oracles {
		prefix := fmt.Sprintf("oracles[%d]", i)
		if o.ID == "" {
			return fmt.Errorf("%s.id: must not be empty", prefix)
		}
		if seen[o.ID] {
			return fmt.Errorf("%s.id: duplicate id %q", prefix, o.ID)
		}
		seen[o.ID] = true
		if o.PoC == "" {
			return fmt.Errorf("%s.poc: must not be empty", prefix)
		}
		info, err := os.Stat(o.pocFile)
		if err != nil {
			return fmt.Errorf("%s.poc: %w", prefix, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s.poc: %s is not a regular file", prefix, o.PoC)
		}
		if o.Repeats < 1 {
			return fmt.Errorf("%s.repeats: must be at least 1", prefix)
		}
		if o.TimeoutSec < 1 {
			return fmt.Errorf("%s.timeout_sec: must be at least 1", prefix)
		}
		if o.FiredWhen.Exit != nil && (*o.FiredWhen.Exit < 0 || *o.FiredWhen.Exit > 255) {
			return fmt.Errorf("%s.fired_when.exit: must be between 0 and 255", prefix)
		}
		if o.FiredWhen.SilentExit != nil {
			if *o.FiredWhen.SilentExit < 0 || *o.FiredWhen.SilentExit > 255 {
				return fmt.Errorf("%s.fired_when.silent_exit: must be between 0 and 255", prefix)
			}
			if *o.FiredWhen.SilentExit == o.FiredWhen.ExitCode() {
				return fmt.Errorf("%s.fired_when.silent_exit: must differ from fired_when.exit (%d)", prefix, o.FiredWhen.ExitCode())
			}
		}
	}

	switch s.Regression.Parser {
	case "", ParserExitCode, ParserJUnitXML:
	default:
		return fmt.Errorf("regression.parser: %q is not one of %s, %s",
			s.Regression.Parser, ParserExitCode, ParserJUnitXML)
	}
	return nil
}

func validateService(s Service) error {
	if !s.Enabled() {
		if s.Port != 0 {
			return errors.New("target.service.port: requires target.service.cmd")
		}
		return nil
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("target.service.port: %d is not a valid TCP port", s.Port)
	}
	if s.ReadyTimeoutSec < 1 {
		return errors.New("target.service.ready_timeout_sec: must be at least 1")
	}
	return nil
}
