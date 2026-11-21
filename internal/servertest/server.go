// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// readyLine is what the server logs when it is ready for clients.
const readyLine = "Initialization Sequence Completed"

// startAttempts is how often Start tries again when the port it picked was
// taken by someone else between the pick and the bind.
const startAttempts = 3

// devCounter makes the names of the tun devices different inside one process;
// the process id makes them different between the test programs that
// `go test ./...` runs at the same time in the same namespace.
var devCounter atomic.Uint32

// Options say how to start a server. The zero value is a UDP server with
// DCO enabled where the kernel has it, on 10.8.0.0/24, that requires a client
// certificate from the PKI (OpenVPN's default). A test that wants clients with
// no certificate adds --verify-client-cert none and an authentication method
// to Extra: the server refuses the first without the second.
type Options struct {
	// Proto is "udp" (the default) or "tcp".
	Proto string
	// DisableDCO adds --disable-dco: the data channel then runs in the
	// openvpn process and not in the kernel.
	DisableDCO bool
	// Subnet is the network of the tunnel; the server is its first host.
	// The default is 10.8.0.0/24. A test that runs two servers at once gives
	// each its own, and `go test -p 1` keeps the test programs apart.
	Subnet netip.Prefix
	// Extra is more command line options, added after the ones of Start.
	Extra []string
	// PKI is the certificates the server uses; Start makes one when it is nil.
	PKI *PKI
}

// Server is a running openvpn server.
type Server struct {
	// PKI has the certificates of the server.
	PKI *PKI

	proto   string
	port    int
	subnet  netip.Prefix
	logPath string
	cmd     *exec.Cmd
	done    chan struct{} // closed when the process has exited and was waited for
}

// config is what buildArgs turns into a command line.
type config struct {
	pki        *PKI
	proto      string
	port       int
	dev        string
	subnet     netip.Prefix
	logPath    string
	disableDCO bool
	extra      []string
}

// Start starts a server and returns when it is ready. It stops the server, and
// waits for it to exit, when the test ends. It skips the test when openvpn is
// not installed or when the test is not running under scripts/vpn-ns.sh.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("servertest: openvpn is not installed")
	}
	if os.Getenv("GOPENVPN_NS") != "1" {
		t.Skip("servertest: not inside the namespace of scripts/vpn-ns.sh")
	}
	proto := opts.Proto
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		t.Fatalf("servertest: Proto is %q, want udp or tcp", opts.Proto)
	}
	subnet := opts.Subnet
	if !subnet.IsValid() {
		subnet = netip.MustParsePrefix("10.8.0.0/24")
	}
	if !subnet.Addr().Is4() || subnet.Bits() > 29 {
		t.Fatalf("servertest: Subnet %v is not an IPv4 network of at least 8 addresses", subnet)
	}
	pki := opts.PKI
	if pki == nil {
		pki = NewPKI(t)
	}
	dir := t.TempDir()

	for attempt := 1; attempt <= startAttempts; attempt++ {
		port := freePort(t, proto)
		s := &Server{
			PKI:     pki,
			proto:   proto,
			port:    port,
			subnet:  subnet.Masked(),
			logPath: filepath.Join(dir, "server-"+strconv.Itoa(attempt)+".log"),
			done:    make(chan struct{}),
		}
		args := buildArgs(config{
			pki:        pki,
			proto:      proto,
			port:       port,
			dev:        fmt.Sprintf("tungo%d_%d", os.Getpid(), devCounter.Add(1)%100),
			subnet:     subnet,
			logPath:    s.logPath,
			disableDCO: opts.DisableDCO,
			extra:      opts.Extra,
		})
		if failure := s.launch(t, args); failure != "" {
			if strings.Contains(failure, "Address already in use") && attempt < startAttempts {
				continue
			}
			t.Fatalf("servertest: openvpn did not start (attempt %d):\n%s", attempt, failure)
		}
		t.Cleanup(func() { s.stop(t) })
		return s
	}
	t.Fatal("servertest: unreachable")
	return nil
}

// buildArgs is the command line of a server.
func buildArgs(c config) []string {
	network := c.subnet.Masked().Addr()
	mask := net.IP(net.CIDRMask(c.subnet.Bits(), 32)).String()
	args := []string{
		"--mode", "server",
		"--tls-server",
		"--dev", c.dev,
		"--topology", "subnet",
		"--server", network.String(), mask,
		"--proto", c.proto,
		"--local", "127.0.0.1",
		"--port", strconv.Itoa(c.port),
		"--ca", c.pki.CAFile,
		"--cert", c.pki.ServerCertFile,
		"--key", c.pki.ServerKeyFile,
		"--dh", "none",
		"--verb", "4",
		"--log", c.logPath,
	}
	if c.disableDCO {
		args = append(args, "--disable-dco")
	}
	return append(args, c.extra...)
}

// freePort asks the system for a free port on the loopback. Another program
// may take it before the server binds it: Start tries again then.
func freePort(t testing.TB, proto string) int {
	t.Helper()
	if proto == "tcp" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("servertest: find a free TCP port (is the loopback up?): %v", err)
		}
		defer closeOrLog(t, l)
		return l.Addr().(*net.TCPAddr).Port
	}
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("servertest: find a free UDP port (is the loopback up?): %v", err)
	}
	defer closeOrLog(t, c)
	return c.LocalAddr().(*net.UDPAddr).Port
}

// closeOrLog closes c and reports a failure in the log of the test.
func closeOrLog(t testing.TB, c io.Closer) {
	if err := c.Close(); err != nil {
		t.Logf("servertest: close: %v", err)
	}
}

// launch starts the process and waits until the server is ready. It returns
// "" on success, and on failure the reason with the log, after stopping the
// process.
func (s *Server) launch(t testing.TB, args []string) string {
	t.Helper()
	s.cmd = exec.Command("openvpn", args...)
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.cmd.Start(); err != nil {
		return "cannot run openvpn: " + err.Error()
	}
	go func() {
		// The result is read by stop; here it only has to be collected.
		_ = s.cmd.Wait()
		close(s.done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.Log(), readyLine) {
			return ""
		}
		select {
		case <-s.done:
			return "openvpn exited before it was ready:\n" + s.Log()
		case <-time.After(25 * time.Millisecond):
		}
	}
	s.stop(t)
	return "openvpn was not ready after 10 seconds:\n" + s.Log()
}

// Stop ends the server now, without waiting for the end of the test, and
// returns when the process has been waited for. It is safe to call more than
// once; the cleanup of Start calls it again.
func (s *Server) Stop(t testing.TB) {
	t.Helper()
	s.stop(t)
}

// stop ends the server's process group: SIGTERM, and SIGKILL if it is still
// there after 3 seconds. It returns when the process has been waited for.
func (s *Server) stop(t testing.TB) {
	select {
	case <-s.done:
		return
	default:
	}
	pgid := s.cmd.Process.Pid
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		t.Logf("servertest: SIGTERM to the server: %v", err)
	}
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			t.Logf("servertest: SIGKILL to the server: %v", err)
		}
		<-s.done
	}
}

// Network is "udp" or "tcp".
func (s *Server) Network() string { return s.proto }

// Addr is the address clients dial, as host:port on the loopback.
func (s *Server) Addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)) }

// Subnet is the network of the tunnel.
func (s *Server) Subnet() netip.Prefix { return s.subnet }

// TunnelIP is the address of the server inside the tunnel: the first host of
// the subnet, 10.8.0.1 by default.
func (s *Server) TunnelIP() netip.Addr { return s.subnet.Addr().Next() }

// PID is the process id of the server.
func (s *Server) PID() int { return s.cmd.Process.Pid }

// Log is everything the server has logged so far. A log that cannot be read
// yet (the server has not made the file) is empty.
func (s *Server) Log() string {
	data, err := os.ReadFile(filepath.Clean(s.logPath))
	if err != nil {
		return ""
	}
	return string(data)
}

// WaitLog waits until the log has substring, and fails the test with the log
// if it does not within timeout.
func (s *Server) WaitLog(t testing.TB, substring string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(s.Log(), substring) {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("servertest: the server did not log %q within %v; its log:\n%s", substring, timeout, s.Log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}
