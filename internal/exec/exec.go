// Package exec is the only package that touches processes: it builds the
// target, starts and stops its service, and runs commands while recording the
// exit code, output, and duration every oracle and regression observation
// needs.
package exec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result is one finished process. A non-zero ExitCode is not a Go error: the
// caller decides what an exit code means for its oracle.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	// StdoutSHA256 is the digest of the full stdout stream, not of the bounded
	// Stdout prefix kept for diagnostics and pattern matching.
	StdoutSHA256 string
	Duration     time.Duration
}

// RunShell runs a shell command line in dir and waits for it. It is how spec
// command strings such as "go build ./..." are interpreted.
func RunShell(ctx context.Context, dir, line string, env map[string]string) (Result, error) {
	return run(ctx, dir, "sh", []string{"-c", line}, env)
}

// RunFile runs an executable PoC file. A file without an executable bit is
// handed to sh, so a checked-out script works regardless of its mode; an
// executable file is run directly and its shebang picks the interpreter.
func RunFile(ctx context.Context, dir, path string, env map[string]string) (Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, err
	}
	if info.Mode().Perm()&0o111 != 0 {
		return run(ctx, dir, path, nil, env)
	}
	return run(ctx, dir, "sh", []string{path}, env)
}

func run(ctx context.Context, dir, name string, args []string, env map[string]string) (Result, error) {
	start := time.Now()
	cmd := osexec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = mergeEnv(env)
	// A command may spawn children (a shell that backgrounds work, a compiler
	// with helpers). Killing only the direct child on expiry would leave them
	// running, so the child gets its own process group and the whole group is
	// signalled. proc_unix.go and proc_windows.go own the platform difference.
	isolateProcessGroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay

	stdout, stderr := newCapture(), newCapture()
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	res := Result{
		Stdout:       stdout.Bytes(),
		Stderr:       stderr.Bytes(),
		StdoutSHA256: stdout.SHA256(),
		Duration:     time.Since(start),
	}
	if err == nil {
		return res, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}
	var exitErr *osexec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

// Service is a started long-running process. Stop must be called; it is safe
// to call more than once and after the process already exited.
type Service struct {
	cmd    *osexec.Cmd
	output *capture
	exited chan struct{}
}

// waitDelay bounds how long a cancelled command may keep its I/O pipes open
// after the process group was killed.
const waitDelay = 2 * time.Second

// StartService starts a shell command line in dir in its own process group so
// Stop can signal the whole tree. Its stdout and stderr are captured, bounded,
// for diagnostics when readiness fails.
func StartService(dir, line string, env map[string]string) (*Service, error) {
	cmd := osexec.Command("sh", "-c", line)
	cmd.Dir = dir
	cmd.Env = mergeEnv(env)
	isolateProcessGroup(cmd)

	s := &Service{
		output: newCapture(),
		exited: make(chan struct{}),
	}
	cmd.Stdout = s.output
	cmd.Stderr = s.output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.cmd = cmd
	go func() {
		_ = cmd.Wait()
		close(s.exited)
	}()
	return s, nil
}

// stopGrace is how long Stop waits for a clean exit before killing.
const stopGrace = 5 * time.Second

// WaitReady polls a TCP connection to 127.0.0.1:port until it succeeds, the
// service exits, ctx is cancelled, or timeout elapses.
func (s *Service) WaitReady(ctx context.Context, port int, timeout time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-s.exited:
			return fmt.Errorf("service exited before accepting connections on %s%s", addr, s.diagnostic())
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}

		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("service did not accept connections on %s within %s%s",
				addr, timeout, s.diagnostic())
		}
	}
}

// Stop terminates the service's process group, escalating to SIGKILL when the
// grace period expires.
func (s *Service) Stop() {
	if s == nil || s.cmd == nil {
		return
	}
	select {
	case <-s.exited:
		return
	default:
	}

	_ = terminateGroup(s.cmd)
	select {
	case <-s.exited:
		return
	case <-time.After(stopGrace):
	}
	_ = killGroup(s.cmd)
	<-s.exited
}

// Output returns the captured service output so far.
func (s *Service) Output() string { return s.output.String() }

func (s *Service) diagnostic() string {
	if out := tail(s.output.String(), 800); out != "" {
		return "\nservice output:\n" + out
	}
	return ""
}

// mergeEnv layers spec overrides on top of the process environment. Building
// one slice instead of appending keeps the override unambiguous.
func mergeEnv(overrides map[string]string) []string {
	env := os.Environ()
	if len(overrides) == 0 {
		return env
	}
	index := make(map[string]int, len(env))
	for i, kv := range env {
		if key, _, ok := strings.Cut(kv, "="); ok {
			index[key] = i
		}
	}
	for key, value := range overrides {
		kv := key + "=" + value
		if i, ok := index[key]; ok {
			env[i] = kv
		} else {
			index[key] = len(env)
			env = append(env, kv)
		}
	}
	return env
}

// tail returns at most the last max bytes of s, trimmed of surrounding space.
func tail(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max:]
}

const maxCapturedOutput = 64 << 10

// capture is a concurrency-safe output sink with a hard cap. It keeps the first
// maxCapturedOutput bytes for diagnostics and pattern matching, but hashes every
// byte as it streams, so a noisy command cannot grow the gate's memory without
// bound and the digest still covers the full output.
type capture struct {
	mu  sync.Mutex
	buf bytes.Buffer
	h   hash.Hash
}

func newCapture() *capture { return &capture{h: sha256.New()} }

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.h.Write(p)
	if room := maxCapturedOutput - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// Bytes returns the bounded prefix that was retained.
func (c *capture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// SHA256 is the hex digest of every byte written, including the part dropped
// once the cap was reached.
func (c *capture) SHA256() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return hex.EncodeToString(c.h.Sum(nil))
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
