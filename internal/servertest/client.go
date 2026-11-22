// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ClientProc is a running openvpn client: the real program, used to show that a
// profile that the library reads is one that OpenVPN accepts.
type ClientProc struct {
	logPath string
	cmd     *exec.Cmd
	done    chan struct{} // closed when the process has exited and was waited for
}

// StartClient runs `openvpn --config profile` in dir (the profile's own files are
// found there, as they are for ParseFS) with no tun device and no change to the
// addresses or the routes of the machine: --dev null --ifconfig-noexec
// --route-noexec. It does not wait for anything: use WaitLog. The process runs in
// its own process group and is stopped when the test ends. It skips the test under
// the same conditions as Start.
func StartClient(t testing.TB, dir, profile string, extra ...string) *ClientProc {
	t.Helper()
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("servertest: openvpn is not installed")
	}
	if os.Getenv("GOPENVPN_NS") != "1" {
		t.Skip("servertest: not inside the namespace of scripts/vpn-ns.sh")
	}
	c := &ClientProc{
		logPath: filepath.Join(t.TempDir(), "client.log"),
		done:    make(chan struct{}),
	}
	args := []string{
		"--cd", dir,
		"--config", profile,
		"--dev", "null",
		"--ifconfig-noexec", "--route-noexec",
		"--disable-dco",
		"--verb", "4",
		"--log", c.logPath,
	}
	c.cmd = exec.Command("openvpn", append(args, extra...)...)
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.cmd.Start(); err != nil {
		t.Fatalf("servertest: cannot run the openvpn client: %v", err)
	}
	go func() {
		// The result is not needed; the process only has to be collected.
		_ = c.cmd.Wait()
		close(c.done)
	}()
	t.Cleanup(func() { c.stop(t) })
	return c
}

// Log is everything the client has logged so far.
func (c *ClientProc) Log() string {
	data, err := os.ReadFile(filepath.Clean(c.logPath))
	if err != nil {
		return ""
	}
	return string(data)
}

// Wait waits until the client's log has substring, and fails the test with the log
// if it does not within timeout or if the client exits first.
func (c *ClientProc) Wait(t testing.TB, substring string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(c.Log(), substring) {
			return
		}
		select {
		case <-c.done:
			if strings.Contains(c.Log(), substring) {
				return
			}
			t.Fatalf("servertest: the openvpn client exited before it logged %q; its log:\n%s", substring, c.Log())
		default:
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("servertest: the openvpn client did not log %q within %v; its log:\n%s", substring, timeout, c.Log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Stop ends the client now: SIGTERM to its process group, SIGKILL after 3 seconds.
// It is safe to call more than once.
func (c *ClientProc) Stop(t testing.TB) {
	t.Helper()
	c.stop(t)
}

func (c *ClientProc) stop(t testing.TB) {
	select {
	case <-c.done:
		return
	default:
	}
	pgid := c.cmd.Process.Pid
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		t.Logf("servertest: SIGTERM to the client: %v", err)
	}
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			t.Logf("servertest: SIGKILL to the client: %v", err)
		}
		<-c.done
	}
}
