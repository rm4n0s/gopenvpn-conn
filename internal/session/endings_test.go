// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

func TestServerEndingsEndTheSession(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		tag      string
		route    string
		metadata map[string]any
	}{
		{"auth failed", "AUTH_FAILED,wrong password", TagAuthFailed, routeControl + ".AuthFailed",
			map[string]any{"reason": "wrong password", "session": false, "temporary": false, "backoff": 0, "advance": ""}},
		{"auth failed with no reason", "AUTH_FAILED", TagAuthFailed, routeControl + ".AuthFailed",
			map[string]any{"reason": ""}},
		{"auth failed, token expired", "AUTH_FAILED,SESSION:token expired", TagAuthFailed, routeControl + ".AuthFailed",
			map[string]any{"session": true, "reason": "token expired"}},
		{"auth failed, temporary", "AUTH_FAILED,TEMP[backoff 42,advance no]:busy", TagAuthFailed, routeControl + ".AuthFailed",
			map[string]any{"temporary": true, "backoff": 42, "advance": "no", "reason": "busy"}},
		{"halt", "HALT,server is going down", TagServerHalt, routeControl + ".ServerHalt",
			map[string]any{"reason": "server is going down"}},
		{"restart", "RESTART,[PN]reloading", TagServerRestart, routeControl + ".ServerRestart",
			map[string]any{"reason": "reloading", "flags": "PN"}},
	}
	for _, tt := range tests {
		for _, when := range []string{"early", "instead of the reply"} {
			t.Run(tt.name+"/"+when, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					opts := vpntest.ServerOptions{}
					if when == "early" {
						opts.EarlyMessages = []string{tt.message}
					} else {
						opts.PushMessages = []string{tt.message}
					}
					r := pushRig(t, opts)
					err := r.session.Handshake(t.Context())
					appErr, ok := errors.FromError(err)
					if !ok || appErr.Tag != tt.tag || !appErr.HasRoute(tt.route) {
						t.Fatalf("Handshake = %v (route %v), want %s with route %s", err, appErr, tt.tag, tt.route)
					}
					for k, want := range tt.metadata {
						if appErr.Metadata[k] != want {
							t.Errorf("metadata %q = %#v, want %#v", k, appErr.Metadata[k], want)
						}
					}
					if r.session.Pushed() != nil {
						t.Error("Pushed() is not nil after the session ended")
					}
					// Every later call returns the very same error.
					if again := r.session.Handshake(t.Context()); again != err {
						t.Errorf("a second Handshake returned %v, want the same error", again)
					}
					synctest.Wait()
				})
			})
		}
	}
}

func TestServerEndingAfterTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := pushRig(t, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		r.server.SendControl("HALT,later")
		synctest.Wait()
		err := r.session.Handshake(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagServerHalt || appErr.Metadata["reason"] != "later" {
			t.Fatalf("Handshake after the HALT = %v, want %s", err, TagServerHalt)
		}
	})
}

func TestAuthPendingExtendsTheHandshake(t *testing.T) {
	t.Run("the reply comes after the usual timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// 12 requests, 5 seconds apart: the reply is at 55 seconds, past the 30 of the timeout.
			r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"AUTH_PENDING,timeout 120"}, ReplyAfterRequests: 12})
			start := time.Now()
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatalf("Handshake = %v, want success after %v", err, time.Since(start))
			}
			if elapsed := time.Since(start); elapsed < 50*time.Second {
				t.Errorf("the handshake took %v, want more than the timeout of %v", elapsed, handshakeTimeout)
			}
		})
	})
	t.Run("the extended time is the end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"AUTH_PENDING,timeout 120"}, PushMessages: []string{}})
			start := time.Now()
			err := r.session.Handshake(t.Context())
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
				t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
			}
			if elapsed := time.Since(start); elapsed != 120*time.Second {
				t.Errorf("failed after %v, want 120s", elapsed)
			}
		})
	})
	t.Run("a shorter time never shortens it", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := pushRig(t, vpntest.ServerOptions{
				EarlyMessages: []string{"AUTH_PENDING,timeout 120", "AUTH_PENDING,timeout 10"}, PushMessages: []string{}})
			start := time.Now()
			err := r.session.Handshake(t.Context())
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
				t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
			}
			if elapsed := time.Since(start); elapsed != 120*time.Second {
				t.Errorf("failed after %v, want 120s", elapsed)
			}
		})
	})
	t.Run("a huge time is cut to the limit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"AUTH_PENDING,timeout 999999"}, PushMessages: []string{}})
			start := time.Now()
			err := r.session.Handshake(t.Context())
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
				t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
			}
			if elapsed := time.Since(start); elapsed != maxAuthPending {
				t.Errorf("failed after %v, want %v", elapsed, maxAuthPending)
			}
		})
	})
	t.Run("AUTH_PENDING without a time keeps the timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := pushRig(t, vpntest.ServerOptions{EarlyMessages: []string{"AUTH_PENDING"}, PushMessages: []string{}})
			start := time.Now()
			err := r.session.Handshake(t.Context())
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
				t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
			}
			if elapsed := time.Since(start); elapsed != handshakeTimeout {
				t.Errorf("failed after %v, want %v", elapsed, handshakeTimeout)
			}
		})
	})
	t.Run("a flood of them is harmless", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			many := make([]string, 200)
			for i := range many {
				many[i] = "AUTH_PENDING,timeout " + strings.Repeat("9", 3)
			}
			r := pushRig(t, vpntest.ServerOptions{EarlyMessages: many})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		})
	})
}

// The latest end that AUTH_PENDING asked for wins, in whatever order its messages
// are handled: two of them in a row, before the loop looks, must not leave the
// shorter one (a race that the first version of extendHandshake had).
func TestExtendHandshakeKeepsTheLatestEnd(t *testing.T) {
	for _, order := range [][]time.Duration{{120 * time.Second, 10 * time.Second}, {10 * time.Second, 120 * time.Second}} {
		s := New(Options{Link: &net.UDPConn{}, Err: errors.New(tagNeverStarts, "a session that never starts")})
		for _, asked := range order {
			s.extendHandshake(asked)
		}
		if want := s.began.Add(120 * time.Second); !s.extendAt.Equal(want) {
			t.Errorf("order %v: the end is %v after the start, want 120s", order, s.extendAt.Sub(s.began))
		}
		if len(s.extend) != 1 {
			t.Errorf("order %v: %d wake-ups waiting, want 1", order, len(s.extend))
		}
	}
}
