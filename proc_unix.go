//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach отрывает процесс от группы xsub: opkg остановит xsub, а установка должна дожить до конца.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
