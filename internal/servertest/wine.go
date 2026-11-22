// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// wineMu makes the Wine prefix once for the test program.
var wineMu sync.Mutex

// moduleRoot is the directory with go.mod above the working directory of the test.
func moduleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("servertest: working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("servertest: no go.mod above the working directory")
		}
		dir = parent
	}
}

// wineEnv is the environment of every Wine process of the tests (the same as
// scripts/wine-exec.sh): the prefix is .wine-test/prefix in the module root.
func wineEnv(root string) []string {
	return append(os.Environ(),
		"WINEPREFIX="+filepath.Join(root, ".wine-test", "prefix"),
		"WINEDEBUG=-all",
		"WINEARCH=win64",
		"WINEDLLOVERRIDES=mscoree,mshtml=",
	)
}

// RunWine runs a Windows program under Wine (scripts/wine-exec.sh) and returns what it
// wrote, its standard output and error together, without the lines that Wine's
// graphics libraries print. The process runs in its own process group, which is
// killed when ctx ends, and Wine's server is stopped (wineserver -k) when the test
// ends. It skips the test when wine is not installed.
func RunWine(ctx context.Context, t testing.TB, exe string, args ...string) ([]byte, error) {
	t.Helper()
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("servertest: wine is not installed")
	}
	root := moduleRoot(t)
	env := wineEnv(root)
	wineMu.Lock()
	if _, err := os.Stat(filepath.Join(root, ".wine-test", "prefix", "system.reg")); err != nil {
		if err := os.MkdirAll(filepath.Join(root, ".wine-test", "prefix"), 0o750); err != nil {
			wineMu.Unlock()
			t.Fatalf("servertest: make the Wine prefix: %v", err)
		}
		cmd := exec.Command("timeout", "-k", "5", "300", "wineboot", "--init")
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			wineMu.Unlock()
			t.Fatalf("servertest: wineboot --init: %v\n%s", err, out)
		}
	}
	wineMu.Unlock()
	t.Cleanup(func() {
		cmd := exec.Command("timeout", "-k", "5", "30", "wineserver", "-k")
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		// It exits with 1 when no server is running, which is what we want.
		if err := cmd.Run(); err != nil && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() != 1 {
			t.Logf("servertest: wineserver -k: %v", err)
		}
	})

	cmd := exec.Command(filepath.Join(root, "scripts", "wine-exec.sh"), append([]string{exe}, args...)...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// The output goes to a file, not to a pipe: the Wine server that this process
	// starts keeps what it inherited open for a few seconds after the program has
	// ended, and Wait would wait for a pipe to close as long.
	outFile, err := os.CreateTemp(t.TempDir(), "wine-output-*")
	if err != nil {
		t.Fatalf("servertest: make the output file: %v", err)
	}
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			t.Logf("servertest: close the output file: %v", cerr)
		}
	}()
	cmd.Stdout, cmd.Stderr = outFile, outFile
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		pgid := cmd.Process.Pid
		if kerr := syscall.Kill(-pgid, syscall.SIGKILL); kerr != nil && kerr != syscall.ESRCH {
			t.Logf("servertest: kill the Wine process group: %v", kerr)
		}
		select {
		case err = <-done:
		case <-time.After(10 * time.Second):
			err = ctx.Err()
		}
	}
	out, rerr := os.ReadFile(outFile.Name())
	if rerr != nil {
		t.Fatalf("servertest: read the output: %v", rerr)
	}
	return dropGraphicsNoise(out), err
}

// dropGraphicsNoise removes the lines that Mesa prints when Wine starts in a session
// with no usable display.
func dropGraphicsNoise(b []byte) []byte {
	var out [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("MESA")) || bytes.HasPrefix(line, []byte("pci id")) {
			continue
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\n"))
}
