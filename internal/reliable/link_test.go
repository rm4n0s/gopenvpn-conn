// SPDX-License-Identifier: GPL-2.0-only

package reliable

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// lossyLink delivers items after a random number of steps, loses some and
// repeats some. Items sent in one step may arrive in any order.
type lossyLink[T any] struct {
	rng            *rand.Rand
	loss, dup      float64
	maxDelaySteps  int
	inFlight       []inFlight[T]
	lost, repeated int
}

type inFlight[T any] struct {
	at   int
	item T
}

func (l *lossyLink[T]) send(step int, item T) {
	if l.rng.Float64() < l.loss {
		l.lost++
		return
	}
	copies := 1
	if l.rng.Float64() < l.dup {
		copies = 2
		l.repeated++
	}
	for i := 0; i < copies; i++ {
		l.inFlight = append(l.inFlight, inFlight[T]{at: step + l.rng.Intn(l.maxDelaySteps+1), item: item})
	}
}

// arrived returns what is due at this step, in a random order.
func (l *lossyLink[T]) arrived(step int) []T {
	var out []T
	rest := l.inFlight[:0]
	for _, f := range l.inFlight {
		if f.at <= step {
			out = append(out, f.item)
		} else {
			rest = append(rest, f)
		}
	}
	l.inFlight = rest
	l.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

type ackPacket struct{ ids []uint32 }

// TestRandomLinkDeliversEveryPayloadOnceInOrder runs a Sender and a Receiver
// over links that lose, repeat and reorder, in virtual time, for seeds and
// kinds of links that are fixed.
func TestRandomLinkDeliversEveryPayloadOnceInOrder(t *testing.T) {
	const (
		payloads = 150
		step     = 250 * time.Millisecond
		maxSteps = 400000
	)
	links := []struct {
		name          string
		loss, dup     float64
		maxDelaySteps int
	}{
		{"clean", 0, 0, 0},
		{"reorder only", 0, 0, 8},
		{"duplicates", 0, 0.5, 4},
		{"10% loss", 0.1, 0.05, 4},
		{"30% loss", 0.3, 0.1, 8},
		{"60% loss", 0.6, 0.2, 12},
	}
	for _, lk := range links {
		for seed := int64(1); seed <= 12; seed++ {
			t.Run(fmt.Sprintf("%s/seed %d", lk.name, seed), func(t *testing.T) {
				rng := rand.New(rand.NewSource(seed))
				toReceiver := &lossyLink[Outgoing]{rng: rng, loss: lk.loss, dup: lk.dup, maxDelaySteps: lk.maxDelaySteps}
				toSender := &lossyLink[ackPacket]{rng: rng, loss: lk.loss, dup: lk.dup, maxDelaySteps: lk.maxDelaySteps}
				s := NewSender(2 * time.Second)
				var r Receiver
				var got []string
				queued := 0
				for i := 0; i < maxSteps && len(got) < payloads; i++ {
					now := base.Add(time.Duration(i) * step)
					for queued < payloads && s.CanSend() {
						if _, err := s.Queue(wire.ControlV1, []byte(fmt.Sprintf("payload %d", queued))); err != nil {
							t.Fatal(err)
						}
						queued++
					}
					if s.Len() > SendWindow {
						t.Fatalf("%d packets wait, the window is %d", s.Len(), SendWindow)
					}
					for _, o := range s.Due(now) {
						toReceiver.send(i, o)
					}
					for _, o := range toReceiver.arrived(i) {
						deliver, _ := r.Receive(o.ID, o.Payload)
						for _, d := range deliver {
							got = append(got, string(d))
						}
						if len(r.ahead) >= ReceiveWindow {
							t.Fatalf("%d packets are kept ahead", len(r.ahead))
						}
					}
					if r.HasPendingAcks() {
						toSender.send(i, ackPacket{ids: r.Acks(MaxAcks)})
					}
					for _, a := range toSender.arrived(i) {
						for _, id := range a.ids {
							s.Ack(id)
						}
					}
				}
				if len(got) != payloads {
					t.Fatalf("%d of %d payloads delivered (link lost %d and repeated %d packets)",
						len(got), payloads, toReceiver.lost, toReceiver.repeated)
				}
				for i, g := range got {
					if want := fmt.Sprintf("payload %d", i); g != want {
						t.Fatalf("payload %d is %q, want %q", i, g, want)
					}
				}
			})
		}
	}
}
