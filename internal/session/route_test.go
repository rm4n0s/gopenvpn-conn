// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// How the routes of the errors that the goroutines of a session make begin. The
// Handshake that starts the session hands their work off (Session.start), so the
// route of such an error is the chain of calls from that Handshake on.
const (
	// routeStart is in front of the function that a goroutine of the session runs.
	routeStart = "Session.Handshake->Session.start->"
	// routeTLS ends at the function of the TLS goroutine of the first key, and
	// routeControl at the one that takes a control message of the server in it.
	routeTLS     = routeStart + "Session.startTLS->Session.startTLS.func1->Session.tlsMain"
	routeControl = routeTLS + "->Session.controlLoop->Session.control"
	// The loop starts the TLS goroutine of a renegotiation: by time (the client's),
	// or for the soft reset of the server.
	routeTLSOfClient = routeStart + "Session.loop->Session.renegTick->Session.beginKey->Session.startTLS->Session.startTLS.func1->Session.tlsMain"
	routeTLSOfServer = routeStart + "Session.loop->Session.handle->Session.acceptSoftReset->Session.beginKey->Session.startTLS->Session.startTLS.func1->Session.tlsMain"
)

// failingCredentials gives the credentials once, for the handshake, and fails when a
// renegotiation asks for them again (AuthNoCache).
func failingCredentials(o *Options) {
	var asked atomic.Int32
	const tagNoPrompt = "NoPrompt"
	o.AuthNoCache = true
	o.Credentials = func(context.Context) (string, string, error) {
		if asked.Add(1) > 1 {
			return "", "", errors.New(tagNoPrompt, "nobody is there to type the password")
		}
		return "alice", "secret", nil
	}
}

// TestRoutesStartAtTheHandshake: the error that ends a session is made in a goroutine
// of the session and returned by the calls of other goroutines. Its route does not
// begin at the top of the goroutine that made it: it begins at the Handshake that
// started the session (the hand-offs of Session.start, errors.Async) and, for the TLS
// goroutine of a renegotiation, goes on through the loop that started it. No frame of
// a goroutine's own start and none of the errors package is in it: each route below is
// one unbroken chain of calls from Handshake to the tag.
func TestRoutesStartAtTheHandshake(t *testing.T) {
	tests := []struct {
		name string
		// end makes a session, has it end, and returns the error that ended it.
		end   func(t *testing.T) error
		tag   string
		route string
	}{
		{
			name: "the loop",
			end: func(t *testing.T) error {
				r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
				return r.session.Handshake(t.Context())
			},
			tag:   TagHandshakeTimeout,
			route: routeStart + "Session.loop.HandshakeTimeout",
		},
		{
			name: "a function that the loop calls",
			end: func(t *testing.T) error {
				r := pushRig(t, vpntest.ServerOptions{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				_, err := r.session.Read(make([]byte, 10)) // the server sends nothing for ping-restart
				return err
			},
			tag:   TagPingTimeout,
			route: routeStart + "Session.loop->Session.keepaliveTick.PingTimeout",
		},
		{
			name: "the reader of the link",
			end: func(t *testing.T) error {
				r, link := errRig(t, transports[0])
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				link.Inject(1, net.ErrClosed)
				sendIgnoringTheEnd(t, r)
				synctest.Wait()
				return r.session.Err()
			},
			tag:   TagLinkFailed,
			route: routeStart + "Session.readLoop.LinkFailed",
		},
		{
			name: "the writer of the link",
			end: func(t *testing.T) error {
				client, peer := vpntest.NewStreamPair()
				closeAtEnd(t, peer)
				s := New(Options{Link: &brokenConn{Conn: client, writeErr: os.ErrPermission}, Stream: true, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute, ResetOnly: true})
				closeAtEnd(t, s)
				return s.Handshake(t.Context())
			},
			tag:   TagLinkFailed,
			route: routeStart + "Session.writeLoop->Session.writeLink.LinkFailed",
		},
		{
			name: "the TLS goroutine of the first key",
			end: func(t *testing.T) error {
				r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0]}, serverPKI: servertest.NewPKI(t)})
				return r.session.Handshake(t.Context())
			},
			tag:   TagTLSHandshakeFailed,
			route: routeTLS + ".TLSHandshakeFailed",
		},
		{
			name: "the control messages of the first key",
			end: func(t *testing.T) error {
				r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"HALT,going down"}})
				return r.session.Handshake(t.Context())
			},
			tag:   TagServerHalt,
			route: routeControl + ".ServerHalt",
		},
		{
			name: "a session that a Read starts",
			end: func(t *testing.T) error {
				r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"AUTH_FAILED,wrong password"}})
				_, err := r.session.Read(make([]byte, 10))
				return err
			},
			tag:   TagAuthFailed,
			route: "Session.Read->Session.awaitReady->" + routeControl + ".AuthFailed",
		},
		{
			name: "the sender of PUSH_REQUEST",
			end: func(t *testing.T) error {
				// The server never answers PUSH_REQUEST, so the client sends it every 5
				// seconds. Then the control channel of the first key is shut under the
				// sender, as it is when a key state is thrown away: the read of the control
				// messages ends with no failure (the key is closing), and a PUSH_REQUEST
				// that is written after that fails.
				r := pushRig(t, vpntest.ServerOptions{PushMessages: []string{}})
				result := make(chan error, 1)
				go func() { result <- r.session.Handshake(t.Context()) }()
				synctest.Wait() // the first request is out, the next is due in 5 seconds
				r.session.ks0.closing.Store(true)
				r.session.ks0.adapter.shut()
				err := <-result
				if appErr, ok := errors.FromError(err); ok && appErr.Metadata["op"] != "write" {
					t.Errorf("metadata = %v, want the op write", appErr.Metadata)
				}
				return err
			},
			tag:   TagControlChannelFailed,
			route: routeStart + "Session.pushRequests.ControlChannelFailed",
		},
		{
			name: "the TLS goroutine of a renegotiation that the client starts",
			end: func(t *testing.T) error {
				r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, failingCredentials)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				_, err := r.session.Read(make([]byte, 10)) // until the renegotiation at 10 s fails
				return err
			},
			tag:   TagCredentialsFailed,
			route: routeTLSOfClient + "->Session.keyExchange.CredentialsFailed",
		},
		{
			name: "the TLS goroutine of a renegotiation that the server starts",
			end: func(t *testing.T) error {
				r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, func(o *Options) {
					o.RenegotiateAfter = 0 // the client only answers
					failingCredentials(o)
				})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				r.server.Renegotiate()
				synctest.Wait()
				return r.session.Err()
			},
			tag:   TagCredentialsFailed,
			route: routeTLSOfServer + "->Session.keyExchange.CredentialsFailed",
		},
		{
			name: "the control messages of a key of a renegotiation",
			end: func(t *testing.T) error {
				// After the renegotiation the server sends its control messages in the TLS
				// session of the new key: the goroutine that reads them was started by the
				// loop, and its error ends the session through the loop.
				r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, nil)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(renegAfter + 2*time.Second)
				synctest.Wait()
				if n := r.server.Renegotiations(); n != 1 {
					t.Fatalf("%d renegotiations, want 1", n)
				}
				r.server.SendControl("HALT,after a renegotiation")
				synctest.Wait()
				err := r.session.Err()
				if appErr, ok := errors.FromError(err); ok && appErr.Metadata["reason"] != "after a renegotiation" {
					t.Errorf("metadata = %v", appErr.Metadata)
				}
				return err
			},
			tag:   TagServerHalt,
			route: routeTLSOfClient + "->Session.controlLoop->Session.control.ServerHalt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				err := tt.end(t)
				appErr, ok := errors.FromError(err)
				if !ok {
					t.Fatalf("expected *errors.Error, got %T: %v", err, err)
				}
				if appErr.Tag != tt.tag || !appErr.HasRoute(tt.route) {
					t.Errorf("unexpected failure path: %s\nwant tag %s and route %s", appErr.Route(), tt.tag, tt.route)
				}
				// The Go runtime is in no route (errors v0.3.0 on), and the hand-off leaves
				// nothing of itself in it.
				for _, frame := range appErr.StackFrames(false) {
					if frame.PackageName == "runtime" || frame.PackageName == "errors" {
						t.Errorf("the route has a frame of package %s: %s", frame.PackageName, appErr.Route())
					}
				}
				synctest.Wait()
			})
		})
	}
}

// TestServerEXITAfterARenegotiationIsEOF: the server's EXIT in the TLS session of a
// key of a renegotiation ends the session through the loop, as every error of that
// goroutine does, and Read still returns io.EOF itself (SPEC §5.3).
func TestServerEXITAfterARenegotiationIsEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, ccExitPush, vpntest.ServerOptions{}, nil)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(renegAfter + 2*time.Second)
		synctest.Wait()
		if n := r.server.Renegotiations(); n != 1 {
			t.Fatalf("%d renegotiations, want 1", n)
		}
		r.server.SendControl("EXIT")
		if _, err := r.session.Read(make([]byte, 10)); err != io.EOF { // compared with ==, as io.Copy does
			t.Errorf("Read = %v, want io.EOF itself", err)
		}
		if err := r.session.Err(); err != io.EOF {
			t.Errorf("Err = %v, want io.EOF", err)
		}
	})
}
