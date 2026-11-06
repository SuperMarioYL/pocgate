//go:build windows

package exec

import "os/exec"

// Windows has no POSIX process groups. pocgate builds and observes there, but
// it can only signal the process it started: a service that forks helpers may
// leave them behind. This is the documented v0.1 limit on Windows targets.
func isolateProcessGroup(cmd *exec.Cmd) {}

func terminateGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
