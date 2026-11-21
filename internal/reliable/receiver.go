// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/reliable.c and ssl_pkt.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package reliable

import "slices"

// Receiver puts the control packets of the peer in order and keeps the
// acknowledgements to send back. The zero value is ready. It is not safe for
// concurrent use.
//
// OpenVPN: reliable.c reliable_wont_break_sequentiality, reliable_not_replay,
// reliable_ack_write, copy_acks_to_mru; ssl.c tls_pre_decrypt.
type Receiver struct {
	next    uint32            // the id that is delivered next
	ahead   map[uint32][]byte // packets that arrived before their turn
	pending []uint32          // ids to acknowledge, not sent yet
	recent  []uint32          // ids acknowledged lately, newest first
}

// Receive takes a packet with the given id and returns the payloads that are
// now in order (none when the packet came early, or is a copy of one already
// taken), and whether the packet is to be acknowledged.
//
// A packet is acknowledged when it is new and not too far ahead, and also when
// it is a copy of one already taken (the acknowledgement may have been lost,
// and until it arrives the peer keeps sending). It is not acknowledged, and not
// kept, when its id is ReceiveWindow or more ahead of the next one, or when
// MaxAcks acknowledgements already wait to be sent: the peer sends it again.
//
// Receive takes over payload: the caller does not change it after the call. A
// hard reset must have id 0; the caller checks that, as it knows the opcode.
func (r *Receiver) Receive(id uint32, payload []byte) (deliver [][]byte, ack bool) {
	if !before(id, r.next+ReceiveWindow) {
		return nil, false
	}
	_, held := r.ahead[id]
	if before(id, r.next) || held {
		return nil, r.acknowledge(id)
	}
	if !r.acknowledge(id) {
		return nil, false
	}
	if id != r.next {
		if r.ahead == nil {
			r.ahead = make(map[uint32][]byte)
		}
		r.ahead[id] = payload
		return nil, true
	}
	deliver = append(deliver, payload)
	r.next++
	for {
		p, ok := r.ahead[r.next]
		if !ok {
			break
		}
		delete(r.ahead, r.next)
		deliver = append(deliver, p)
		r.next++
	}
	return deliver, true
}

// acknowledge puts id in the list to send. It reports false when the list is
// full and id is not in it.
func (r *Receiver) acknowledge(id uint32) bool {
	if slices.Contains(r.pending, id) {
		return true
	}
	if len(r.pending) >= MaxAcks {
		return false
	}
	r.pending = append(r.pending, id)
	return true
}

// HasPendingAcks reports whether an acknowledgement has not been sent yet: a
// packet with nothing else to say (ACK_V1) is needed if no other packet goes
// out soon.
func (r *Receiver) HasPendingAcks() bool {
	return len(r.pending) > 0
}

// Acks returns the ids to put in the next packet, at most limit (and MaxAcks).
// They are the ids that wait to be sent, oldest first, and then, while there is
// room, ids sent in earlier packets, newest first: OpenVPN repeats them so that
// the loss of one packet does not leave the peer without its acknowledgement.
// What waited and fits is sent and is no longer pending.
func (r *Receiver) Acks(limit int) []uint32 {
	if limit <= 0 {
		return nil
	}
	limit = min(limit, MaxAcks)
	n := min(limit, len(r.pending))
	// Newest to oldest, so that the oldest ends up in front.
	for i := n - 1; i >= 0; i-- {
		id := r.pending[i]
		if j := slices.Index(r.recent, id); j >= 0 {
			r.recent = slices.Delete(r.recent, j, j+1)
		}
		r.recent = slices.Insert(r.recent, 0, id)
	}
	if len(r.recent) > MaxAcks {
		r.recent = r.recent[:MaxAcks]
	}
	r.pending = r.pending[:copy(r.pending, r.pending[n:])]
	return slices.Clone(r.recent[:min(limit, len(r.recent))])
}
