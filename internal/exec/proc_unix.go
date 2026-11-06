//go:build unix

package exec

import (
	"os/exec"
	"syscall"
)

// isolateProcessGroup puts the child in its own process group. A command may
// spawn children (a shell that backgrounds work, a compiler with helpers), so a
// timeout has to kill the group rather than the direct child alone.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateGroup asks the whole group to exit and lets the caller wait for it.
func terminateGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// killGroup removes the whole group, after the grace period or on cancellation.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
