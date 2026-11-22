// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// TestTCPSegmentsFitTheLink: the SYNs of a TCP connection of vpnnet cross the tunnel
// with the MSS that ConnectionState gives (20 less over IPv6), so no TCP packet in
// the tunnel is larger than that MSS and its headers: with a tunnel MTU of 1500
// and no clamp, gVisor would send packets of 1500 bytes, which a link with an MTU
// of 1500 carries only as IP fragments (SPEC §10, §21 O32).
func TestTCPSegmentsFitTheLink(t *testing.T) {
	rows := []struct {
		name, dial string
		ip6        bool
		headers    int // the IP and TCP headers without options
	}{
		{"IPv4", "10.8.0.3:7000", false, 40},
		{"IPv6", "[fd00:8::3]:7000", true, 60},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			na, nb, a, b := newNets(t, row.ip6)
			maxMSS := a.conn.ConnectionState().MSS
			if maxMSS != 1400 || b.conn.ConnectionState().MSS != 1400 {
				t.Fatalf("MSS = %d and %d, want 1400", maxMSS, b.conn.ConnectionState().MSS)
			}
			if row.ip6 {
				maxMSS -= 20
			}
			var mu sync.Mutex
			var syns []uint16
			largest := 0
			tap := func(packet []byte) {
				mu.Lock()
				defer mu.Unlock()
				if mss, _, ok := vpntest.SYNMSS(packet); ok {
					syns = append(syns, mss)
				}
				largest = max(largest, len(packet))
			}
			a.tap.Store(&tap)
			b.tap.Store(&tap)

			l, err := nb.Listen("tcp", row.dial)
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer closeOrFail(t, l)
			echoServer(t, l)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			c, err := na.DialContext(ctx, "tcp", row.dial)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer closeOrFail(t, c)
			roundTrip(t, c, payload(1<<20))

			mu.Lock()
			defer mu.Unlock()
			if len(syns) < 2 {
				t.Fatalf("the tunnel carried %d SYNs, want the SYN and the SYN-ACK", len(syns))
			}
			for _, mss := range syns {
				if int(mss) > maxMSS {
					t.Errorf("a SYN crossed the tunnel with an MSS of %d, above %d", mss, maxMSS)
				}
			}
			// TCP options (timestamps) take some of the room, so a packet may be smaller.
			if limit := maxMSS + row.headers; largest > limit {
				t.Errorf("the largest packet in the tunnel is %d bytes, above %d", largest, limit)
			}
		})
	}
}
