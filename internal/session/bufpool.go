// SPDX-License-Identifier: GPL-2.0-only

package session

import "sync"

// packetBuf is a packet in a buffer that is used again: the packets of the data
// channel go from the reader to the loop and from the loop to Read, and each of them
// would otherwise be a new allocation. Anyone who has taken one gives it back with
// put when it is done with the bytes.
type packetBuf struct {
	b      []byte
	pooled bool // put takes it back; a buffer that is not pooled is left to the collector
}

// bufPool is the buffers of one session.
type bufPool struct {
	p sync.Pool
}

// initialBuf is the capacity of a new buffer: more than a packet of the usual MTU
// with the data channel's own bytes. A packet that is larger gets a larger buffer,
// which then stays in the pool.
const initialBuf = 2048

// get returns a buffer with room for n bytes and a length of n.
func (bp *bufPool) get(n int) *packetBuf {
	pb, _ := bp.p.Get().(*packetBuf)
	if pb == nil {
		pb = &packetBuf{b: make([]byte, 0, max(n, initialBuf)), pooled: true}
	}
	if cap(pb.b) < n {
		pb.b = make([]byte, 0, n)
	}
	pb.b = pb.b[:n]
	return pb
}

// put gives a buffer back. The caller must not use it afterwards.
func (bp *bufPool) put(pb *packetBuf) {
	if pb != nil && pb.pooled {
		bp.p.Put(pb)
	}
}
