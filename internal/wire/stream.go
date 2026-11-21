// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"encoding/binary"
	"io"
	"math"

	"github.com/rm4n0s/errors"
)

// MaxFrame is the largest packet that a TCP frame can carry: its length is
// 16 bits.
const MaxFrame = math.MaxUint16

// ReadFrame reads one packet from a TCP stream: a 16-bit length in network byte
// order, then that many bytes, which it reads into buf. It returns the packet,
// a slice of buf. A frame of length 0 is returned as an empty slice.
//
// A frame longer than buf is refused before its bytes are read, so a peer
// cannot make the reader hold more than len(buf); the stream is then out of
// step and the caller ends the connection. When the stream ends between two
// frames the error has io.EOF as its cause (errors.Is finds it); in the middle
// of a frame the cause is io.ErrUnexpectedEOF.
//
// Draft: "OpenVPN wire packet format" (struct tcp_packet).
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, errors.NewErr(tagFrameReadFailed, err).SetMetadata("part", "length")
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n > len(buf) {
		return nil, errors.New(tagFrameTooLarge, "the frame is longer than the buffer", "length", n, "buffer", len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if err == io.EOF {
			// ReadFull says io.EOF when it read nothing at all, but the length
			// was read: the stream ended in the middle of a frame.
			err = io.ErrUnexpectedEOF
		}
		return nil, errors.NewErr(tagFrameReadFailed, err).SetMetadata("part", "packet", "length", n)
	}
	return buf[:n], nil
}

// AppendFrame appends a packet to dst as a TCP frame: its 16-bit length, then
// the packet. It fails when the packet is longer than MaxFrame.
func AppendFrame(dst, packet []byte) ([]byte, error) {
	n := len(packet)
	if n > math.MaxUint16 {
		return dst, errors.New(tagPacketTooLarge, "the packet does not fit a frame", "length", n, "max", MaxFrame)
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(n))
	return append(dst, packet...), nil
}

const (
	tagFrameReadFailed = "FrameReadFailed"
	tagFrameTooLarge   = "FrameTooLarge"
	tagPacketTooLarge  = "PacketTooLarge"
)
