package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunCmdDoesNotWaitForBackgroundOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	out, err := runRestartCmd(ctx, "echo restart-ok; sleep 2 &")
	if err != nil || !strings.Contains(out, "restart-ok") {
		t.Fatalf("output=%q error=%v", out, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("command waited for background process: %v", elapsed)
	}
}

func TestRunCmdReportsErrorAndTimeout(t *testing.T) {
	out, err := runRestartCmd(context.Background(), "echo failed >&2; exit 7")
	if err == nil || !strings.Contains(out, "failed") {
		t.Fatalf("output=%q error=%v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = runRestartCmd(ctx, "exec sleep 2")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout did not stop command promptly: %v", err)
	}
}
