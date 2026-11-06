package exec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunShellBoundsOutputAndHashesFullStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const total = 200000
	res, err := RunShell(ctx, t.TempDir(), "dd if=/dev/zero bs=1000 count=200 2>/dev/null", nil)
	if err != nil {
		t.Fatalf("RunShell: %v", err)
	}
	if len(res.Stdout) != maxCapturedOutput {
		t.Fatalf("captured stdout = %d bytes, want the %d-byte cap", len(res.Stdout), maxCapturedOutput)
	}
	want := sha256.Sum256(bytes.Repeat([]byte{0}, total))
	if res.StdoutSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("stdout sha256 = %s, want the digest of all %d bytes", res.StdoutSHA256, total)
	}
}

func TestRunShellTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	// The backgrounded sleep inherits the command's process group. Killing only
	// the direct shell child would leave it running.
	res, err := RunShell(ctx, dir, "sleep 30 & echo $! > child.pid; wait", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunShell error = %v, want context.DeadlineExceeded", err)
	}
	if res.Duration > 10*time.Second {
		t.Errorf("RunShell took %s, want the deadline to cut it short", res.Duration)
	}

	data, readErr := os.ReadFile(filepath.Join(dir, "child.pid"))
	if readErr != nil {
		t.Fatalf("read child pid: %v (the shell never started the child)", readErr)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if convErr != nil {
		t.Fatalf("child pid %q is not a number: %v", data, convErr)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d is still alive after the command's deadline", pid)
}
