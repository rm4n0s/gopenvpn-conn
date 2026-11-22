// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// renegAfter is the time after which the clients of these tests replace their key.
const renegAfter = 10 * time.Second

// renegRig is a rig whose session renegotiates after renegAfter unless tweak says
// otherwise, over a link and a protection of the test's choice. push is the push reply
// ("" for the usual one).
func renegRig(t *testing.T, tr transport, wrap int, push string, server vpntest.ServerOptions, tweak func(*Options)) *tlsRig {
	t.Helper()
	if push == "" {
		push = vpntest.DefaultPushReply
	}
	server.PushMessages = []string{push}
	server.Epoch = strings.Contains(push, "aead-epoch")
	server.DataV1 = !strings.Contains(push, "peer-id")
	if strings.Contains(push, "dyn-tls-crypt") {
		server.DynamicTLSCrypt = true // the server that pushes the flag does it
	}
	if wrap > 0 && wrapKinds[wrap].static != nil {
		server.StaticKey = wrapKinds[wrap].static(t)
	}
	return newTLSRig(t, tlsOptions{
		rigOptions: rigOptions{transport: tr, wrap: wrapKinds[wrap], server: server},
		ciphers:    allCiphers,
		tweak: func(o *Options) {
			o.RenegotiateAfter = renegAfter
			if tweak != nil {
				tweak(o)
			}
		},
	})
}

// exchange sends a packet each way and checks that both arrive, so the data channel
// works with whatever keys it has now.
func exchange(t *testing.T, r *tlsRig, mark byte) {
	t.Helper()
	before := len(r.server.DataReceived())
	if _, err := r.session.Write([]byte{0x45, 1, mark}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	synctest.Wait()
	got := r.server.DataReceived()
	if len(got) != before+1 || !bytes.Equal(got[before], []byte{0x45, 1, mark}) {
		t.Fatalf("the server got %d packets, want %d (it dropped %d)", len(got), before+1, r.server.DataDropped())
	}
	if _, err := r.server.SendData([]byte{0x45, 2, mark}); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	synctest.Wait()
	buf := make([]byte, 100)
	if err := r.session.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := r.session.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte{0x45, 2, mark}) {
		t.Fatalf("Read = %x, %v", buf[:n], err)
	}
}

// alive has the server send a ping, so that the keepalive of the client does not end
// the session while the test waits.
func alive(t *testing.T, r *tlsRig) {
	t.Helper()
	if err := r.server.SendPing(); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
}

func TestTheClientStartsRenegotiations(t *testing.T) {
	for _, tr := range transports {
		for i, wk := range wrapKinds {
			t.Run(tr.name+"/"+wk.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := renegRig(t, tr, i, "", vpntest.ServerOptions{}, nil)
					if err := r.session.Handshake(t.Context()); err != nil {
						t.Fatal(err)
					}
					exchange(t, r, 1)
					for range 5 {
						time.Sleep(5 * time.Second)
						alive(t, r)
					}
					if n := r.server.Renegotiations(); n < 2 {
						t.Fatalf("%d renegotiations in 25 seconds, want at least 2", n)
					}
					if h := r.server.KeyHistory(); !slices.Equal(h[:3], []uint8{0, 1, 2}) {
						t.Errorf("key ids %v, want 0, 1, 2", h)
					}
					exchange(t, r, 2)
					if err := r.session.Err(); err != nil {
						t.Fatalf("the session ended: %v", err)
					}
				})
			})
		}
	}
}

func TestTheServerStartsRenegotiations(t *testing.T) {
	for _, tr := range transports {
		for i, wk := range wrapKinds {
			t.Run(tr.name+"/"+wk.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					// The client never renegotiates by time here: it only answers.
					r := renegRig(t, tr, i, "", vpntest.ServerOptions{}, func(o *Options) { o.RenegotiateAfter = 0 })
					if err := r.session.Handshake(t.Context()); err != nil {
						t.Fatal(err)
					}
					exchange(t, r, 1)
					r.server.Renegotiate()
					synctest.Wait()
					if n := r.server.Renegotiations(); n != 1 {
						t.Fatalf("%d renegotiations, want 1", n)
					}
					exchange(t, r, 2)
					time.Sleep(3 * time.Second) // the new key is in use on both sides
					r.server.Renegotiate()
					synctest.Wait()
					if h := r.server.KeyHistory(); !slices.Equal(h, []uint8{0, 1, 2}) {
						t.Errorf("key ids %v, want 0, 1, 2", h)
					}
					exchange(t, r, 3)
					if err := r.session.Err(); err != nil {
						t.Fatalf("the session ended: %v", err)
					}
				})
			})
		}
	}
}

func TestBothSidesStartTheSameRenegotiation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, nil)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(renegAfter - time.Millisecond)
		r.server.Renegotiate() // a moment before the client's own time
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if n := r.server.Renegotiations(); n != 1 {
			t.Fatalf("%d renegotiations, want one for the two starts", n)
		}
		exchange(t, r, 1)
		if h := r.server.KeyHistory(); !slices.Equal(h, []uint8{0, 1}) {
			t.Errorf("key ids %v, want 0, 1", h)
		}
	})
}

func TestKeyIDsGoFromOneToSevenAndAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, func(o *Options) {
			o.RenegotiateAfter = 5 * time.Second
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		for range 12 {
			time.Sleep(5 * time.Second)
			alive(t, r)
		}
		h := r.server.KeyHistory()
		if len(h) < 10 || !slices.Equal(h[:10], []uint8{0, 1, 2, 3, 4, 5, 6, 7, 1, 2}) {
			t.Fatalf("key ids %v, want 0, 1, ..., 7, 1, 2", h)
		}
		exchange(t, r, 1)
		if ids := r.server.KeyIDs(); len(ids) != 2 {
			t.Errorf("the server holds keys %v, want two", ids)
		}
	})
}

// TestNoPacketIsLostAcrossRenegotiations sends a numbered packet every 100 ms for a
// minute, and the server echoes each one, while the client renegotiates every 5 seconds
// and the server's own keys change under it.
func TestNoPacketIsLostAcrossRenegotiations(t *testing.T) {
	for _, tr := range transports {
		for _, push := range []string{vpntest.DefaultPushReply, epochPush("AES-256-GCM")} {
			name := tr.name + "/32-bit packet ids"
			if strings.Contains(push, "aead-epoch") {
				name = tr.name + "/epochs"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := renegRig(t, tr, 2, push, vpntest.ServerOptions{EchoData: true}, func(o *Options) {
						o.RenegotiateAfter = 5 * time.Second
					})
					if err := r.session.Handshake(t.Context()); err != nil {
						t.Fatal(err)
					}
					const n = 600
					stop := make(chan struct{})
					defer close(stop) // a failed test must not leave the writer asleep
					go func() {
						for i := range n {
							if _, err := r.session.Write([]byte{0x45, byte(i >> 8), byte(i)}); err != nil {
								return
							}
							select {
							case <-time.After(100 * time.Millisecond):
							case <-stop:
								return
							}
						}
					}()
					buf := make([]byte, 100)
					for i := range n {
						if err := r.session.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
							t.Fatal(err)
						}
						k, err := r.session.Read(buf)
						if err != nil {
							t.Fatalf("Read of packet %d: %v (renegotiations %d)", i, err, r.server.Renegotiations())
						}
						if k != 3 || int(buf[1])<<8|int(buf[2]) != i {
							t.Fatalf("packet %d came as %x", i, buf[:k])
						}
					}
					synctest.Wait()
					if n := r.server.Renegotiations(); n < 8 {
						t.Errorf("only %d renegotiations in a minute", n)
					}
					if d, sd := r.session.Dropped(), r.server.DataDropped(); d != 0 || sd != 0 {
						t.Errorf("the client dropped %d packets and the server %d", d, sd)
					}
				})
			})
		}
	}
}

func TestAFailedRenegotiationIsTriedAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{RejectRenegotiations: 1}, nil)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The first attempt starts at 10 s and gives up at 40 s; the second starts 5
		// seconds later and works. The old key is good until 3610 s.
		for range 5 {
			time.Sleep(10 * time.Second)
			alive(t, r)
			exchange(t, r, 1)
		}
		if n := r.server.Renegotiations(); n != 1 {
			t.Fatalf("%d renegotiations, want 1 (the first was rejected)", n)
		}
		if h := r.server.KeyHistory(); !slices.Equal(h, []uint8{0, 2}) {
			t.Errorf("key ids %v, want 0, 2: the second attempt has the next id", h)
		}
		if err := r.session.Err(); err != nil {
			t.Fatalf("the session ended: %v", err)
		}
	})
}

func TestTheSessionEndsWhenTheOldKeyExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{RejectRenegotiations: 1000}, func(o *Options) {
			o.TransitionWindow = 40 * time.Second
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The renegotiation starts at 10 s, so the old key ends at 50 s.
		for range 5 {
			time.Sleep(10 * time.Second)
			if r.session.Err() == nil {
				alive(t, r)
			}
		}
		synctest.Wait()
		err := r.session.Err()
		if err == nil {
			t.Fatal("the session lives after its key expired")
		}
		wantRoute(t, err, TagRenegotiationFailed, "Session.renegTick->Session.expired.RenegotiationFailed")
		if _, err := r.session.Write([]byte{0x45}); err == nil {
			t.Error("Write works after the session ended")
		}
	})
}

func TestTheOldKeyIsDroppedWhenItsWindowEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, func(o *Options) {
			o.TransitionWindow = 20 * time.Second
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Second) // the renegotiation is done; the old key is lame
		alive(t, r)
		oldKey, err := r.server.SendDataWithKey(0, []byte{0x45, 3, 3})
		if err != nil || oldKey == nil {
			t.Fatalf("SendDataWithKey: %v", err)
		}
		synctest.Wait()
		if d := r.session.Dropped(); d != 0 {
			t.Fatalf("a packet of the old key was dropped inside the window (%d)", d)
		}
		buf := make([]byte, 10)
		if n, err := r.session.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte{0x45, 3, 3}) {
			t.Fatalf("Read = %x, %v", buf[:n], err)
		}
		time.Sleep(10 * time.Second) // past 10 + 20 s
		alive(t, r)
		before := r.session.Dropped()
		if err := r.server.SendPacket(oldKey); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if r.session.Dropped() == before {
			t.Error("a packet of the old key was taken after its window")
		}
		exchange(t, r, 4)
	})
}

func TestTheAuthTokenReplacesThePassword(t *testing.T) {
	user := base64.StdEncoding.EncodeToString([]byte("token-user"))
	tests := []struct {
		name                string
		push                string
		wantUser, wantsPass string
	}{
		{"token and user", vpntest.DefaultPushReply + ",auth-token SESS_ID_abc,auth-token-user " + user, "token-user", "SESS_ID_abc"},
		{"a token only", vpntest.DefaultPushReply + ",auth-token SESS_ID_def", "alice", "SESS_ID_def"},
		{"no token", vpntest.DefaultPushReply, "alice", "secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var asked atomic.Int32
				r := renegRig(t, transports[0], 0, tt.push, vpntest.ServerOptions{}, func(o *Options) {
					o.Credentials = func(context.Context) (string, string, error) {
						asked.Add(1)
						return "alice", "secret", nil
					}
				})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(15 * time.Second)
				alive(t, r)
				kxs := r.server.KeyExchanges()
				if len(kxs) != 2 {
					t.Fatalf("%d key exchanges, want 2", len(kxs))
				}
				if kxs[0].Username != "alice" || kxs[0].Password != "secret" {
					t.Errorf("the first key exchange had %q and a password of %d bytes", kxs[0].Username, len(kxs[0].Password))
				}
				if kxs[1].Username != tt.wantUser || kxs[1].Password != tt.wantsPass {
					t.Errorf("the renegotiation had %q and %q, want %q and %q", kxs[1].Username, kxs[1].Password, tt.wantUser, tt.wantsPass)
				}
				if n := asked.Load(); n != 1 {
					t.Errorf("the credentials were asked for %d times, want once", n)
				}
			})
		})
	}
}

func TestDynamicTLSCrypt(t *testing.T) {
	push := vpntest.DefaultPushReply + ",protocol-flags dyn-tls-crypt"
	for _, tr := range transports {
		for i, wk := range wrapKinds {
			t.Run(tr.name+"/"+wk.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := renegRig(t, tr, i, push, vpntest.ServerOptions{DynamicTLSCrypt: true}, nil)
					if err := r.session.Handshake(t.Context()); err != nil {
						t.Fatal(err)
					}
					for range 3 {
						time.Sleep(10 * time.Second)
						alive(t, r)
					}
					if n := r.server.Renegotiations(); n < 2 {
						t.Fatalf("%d renegotiations with the dynamic key, want at least 2 (dropped: client %d, server %d)",
							n, r.session.Dropped(), r.server.Dropped())
					}
					exchange(t, r, 1)
				})
			})
		}
	}
}

func TestDynamicKeyIsNotUsedWhenTheServerDidNotAsk(t *testing.T) {
	// The server uses the dynamic key and the client does not: they cannot talk, and
	// every renegotiation fails; the old key lives until its window ends.
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 2, "", vpntest.ServerOptions{DynamicTLSCrypt: true}, nil)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Second)
		alive(t, r)
		if n := r.server.Renegotiations(); n != 0 {
			t.Errorf("%d renegotiations, want none", n)
		}
		exchange(t, r, 1)
	})
}

func TestForgedSoftResetsAreDropped(t *testing.T) {
	for i, wk := range wrapKinds[1:] {
		t.Run(wk.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := renegRig(t, transports[0], i+1, "", vpntest.ServerOptions{}, func(o *Options) { o.RenegotiateAfter = 0 })
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				before := r.session.Dropped()
				forged := append([]byte{byte(wire.SoftResetV1)<<3 | 3}, bytes.Repeat([]byte{7}, 80)...)
				if _, err := r.peer.Write(forged); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if r.session.Dropped() != before+1 {
					t.Errorf("dropped %d packets, want %d", r.session.Dropped(), before+1)
				}
				if r.session.keys[3] != nil {
					t.Error("a forged soft reset made a key state")
				}
				exchange(t, r, 1)
			})
		})
	}
}

func TestSoftResetsOfTheWrongSortAreDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{}, func(o *Options) { o.RenegotiateAfter = 0 })
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		inject := func(c wire.Control) {
			t.Helper()
			c.SessionID = r.server.SessionID()
			if err := r.server.Inject(c); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		before := r.session.Dropped()
		inject(wire.Control{Opcode: wire.SoftResetV1, KeyID: 0})                   // a soft reset of key id 0
		inject(wire.Control{Opcode: wire.HardResetServerV2, KeyID: 2})             // a hard reset of another key id
		inject(wire.Control{Opcode: wire.ControlV1, KeyID: 5, Payload: []byte{1}}) // TLS bytes of a key that is not there
		inject(wire.Control{Opcode: wire.SoftResetV1, KeyID: 4, PacketID: 3})      // a reset with an id that is not 0
		if got := r.session.Dropped() - before; got != 4 {
			t.Errorf("dropped %d of 4 packets", got)
		}
		for id, ks := range r.session.keys {
			if id > 0 && ks != nil {
				t.Errorf("key state %d exists", id)
			}
		}
	})
}

func TestTheDataChannelAsksForRenegotiation(t *testing.T) {
	// The 32-bit packet ids near their end, and the AEAD usage limit, make the client
	// renegotiate at once, whatever RenegotiateAfter is.
	tests := []struct {
		name  string
		tweak func(*Options)
		prep  func(t *testing.T, r *tlsRig)
	}{
		{"the packet id", func(o *Options) { o.RenegotiateAfter = 0 }, func(t *testing.T, r *tlsRig) {
			r.session.data.Load().table.Load().send.ch.(interface{ SetNextID(uint32) }).SetNextID(datachan.RenegotiateAt)
		}},
		{"the usage limit", func(o *Options) { o.RenegotiateAfter = 0; o.UsageLimit = 200 }, func(*testing.T, *tlsRig) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := renegRig(t, transports[0], 0, "", vpntest.ServerOptions{EchoData: true}, tt.tweak)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				tt.prep(t, r)
				for i := range 400 {
					if _, err := r.session.Write([]byte{0x45, 1, byte(i)}); err != nil {
						t.Fatalf("Write %d: %v", i, err)
					}
					time.Sleep(10 * time.Millisecond)
				}
				time.Sleep(5 * time.Second)
				synctest.Wait()
				if n := r.server.Renegotiations(); n < 1 {
					t.Fatalf("no renegotiation after the data channel asked for one")
				}
				if got := len(r.server.DataReceived()); got != 400 {
					t.Errorf("the server got %d of 400 packets (it dropped %d)", got, r.server.DataDropped())
				}
			})
		})
	}
}

func TestCloseDuringARenegotiationStopsEveryGoroutine(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := vpntest.BubbleGoroutines()
				r := renegRig(t, tr, 2, "", vpntest.ServerOptions{RejectRenegotiations: 1}, nil)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Second) // the renegotiation is under way, and gets no answer
				if err := r.session.Close(); err != nil {
					t.Fatal(err)
				}
				r.server.Close()
				synctest.Wait()
				if after := vpntest.BubbleGoroutines(); after != before {
					t.Errorf("%d goroutines before, %d after Close", before, after)
				}
			})
		})
	}
}

func TestCloseAfterRenegotiationsStopsEveryGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		before := vpntest.BubbleGoroutines()
		r := renegRig(t, transports[0], 2, "", vpntest.ServerOptions{}, nil)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			time.Sleep(10 * time.Second)
			alive(t, r)
		}
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		r.server.Close()
		synctest.Wait()
		if after := vpntest.BubbleGoroutines(); after != before {
			t.Errorf("%d goroutines before, %d after Close", before, after)
		}
	})
}

func TestANewAuthTokenIsUsedByTheNextRenegotiation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		push := vpntest.DefaultPushReply + ",auth-token SESS_ID_first"
		r := renegRig(t, transports[0], 0, push, vpntest.ServerOptions{}, func(o *Options) {
			o.Credentials = func(context.Context) (string, string, error) { return "alice", "secret", nil }
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		// A server with auth-gen-token sends the new token in a push reply, before the
		// renegotiation at 10 seconds.
		time.Sleep(5 * time.Second)
		r.server.SendControl("PUSH_REPLY,auth-token SESS_ID_second")
		time.Sleep(10 * time.Second)
		alive(t, r)
		kxs := r.server.KeyExchanges()
		if len(kxs) != 2 || kxs[1].Password != "SESS_ID_second" || kxs[1].Username != "alice" {
			t.Fatalf("the renegotiation sent %d exchanges, the last with the password %q", len(kxs), kxs[len(kxs)-1].Password)
		}
	})
}
