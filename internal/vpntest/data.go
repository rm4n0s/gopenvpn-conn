// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// serverData is the data channel of the server: the keys of the TLS exporter,
// used the other way round from the client.
type serverData struct {
	ch   datachan.Channel
	rbuf []byte     // the loop goroutine only
	mu   sync.Mutex // Seal: SendData and the echo run apart
}

// setupData makes the data channel from the TLS session, once the key exchange is
// done. A failure fails the test: the server of a test has no reason to refuse.
func (s *Server) setupData(conn *tls.Conn) {
	cipher, ok := datachan.LookupCipher(s.dataCipher())
	if !ok {
		s.tb.Errorf("vpntest server: no data cipher %q", s.opts.DataCipher)
		return
	}
	state := conn.ConnectionState()
	material, err := state.ExportKeyingMaterial(keys.ExportLabel, nil, keys.DataKeysSize)
	if err != nil {
		s.tb.Errorf("vpntest server: exporting the key material: %v", err)
		return
	}
	dk, err := keys.SplitDataKeys(material)
	if err != nil {
		s.tb.Errorf("vpntest server: %v", err)
		return
	}
	header := datachan.Header{HasPeerID: !s.opts.DataV1}
	var ch datachan.Channel
	if s.opts.Epoch {
		ch, err = datachan.NewEpochChannel(cipher, &dk.ServerToClient, &dk.ClientToServer, header,
			datachan.EpochOptions{Strict: s.opts.Stream, UsageLimit: s.opts.EpochUsageLimit})
	} else {
		ch, err = datachan.NewChannel(cipher, &dk.ServerToClient, &dk.ClientToServer, header, datachan.ReceiverOptions{Strict: s.opts.Stream})
	}
	if err != nil {
		s.tb.Errorf("vpntest server: %v", err)
		return
	}
	s.mu.Lock()
	s.data = &serverData{ch: ch}
	s.mu.Unlock()
}

func (s *Server) dataCipher() string {
	if s.opts.DataCipher == "" {
		return "AES-256-GCM"
	}
	return s.opts.DataCipher
}

// handleData opens a data packet of the client (in the loop goroutine), keeps its
// IP packet for DataReceived and echoes it when the options say so.
func (s *Server) handleData(raw []byte) {
	s.mu.Lock()
	d := s.data
	s.mu.Unlock()
	if d == nil {
		s.mu.Lock()
		s.dataDropped++
		s.mu.Unlock()
		return
	}
	plain, err := d.ch.Open(d.rbuf[:0], raw, time.Now())
	if err != nil {
		s.mu.Lock()
		s.dataDropped++
		s.mu.Unlock()
		return
	}
	d.rbuf = plain[:0]
	packet := bytes.Clone(plain)
	s.mu.Lock()
	s.dataIn = append(s.dataIn, packet)
	s.mu.Unlock()
	if s.opts.EchoData {
		if _, err := s.SendData(packet); err != nil {
			s.writeFailed(err)
		}
	}
}

// SendData seals an IP packet with the server's key and sends it to the client.
// It returns the data packet as it went on the link (without the TCP frame), for
// a test that sends it again.
func (s *Server) SendData(payload []byte) ([]byte, error) {
	s.mu.Lock()
	d := s.data
	s.mu.Unlock()
	if d == nil {
		s.tb.Error("vpntest server: SendData before the key exchange is done")
		return nil, nil
	}
	d.mu.Lock()
	packet, err := d.ch.Seal(nil, payload)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return packet, s.SendPacket(packet)
}

// SendPacket writes a packet of the caller's making to the link, framed when the
// link is a stream, with no protection added.
func (s *Server) SendPacket(packet []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	out := packet
	if s.opts.Stream {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(min(len(packet), math.MaxUint16)))
		out = append(header[:], packet...)
	}
	_, err := s.link.Write(out)
	return err
}

// DataReceived is the IP packets that the server opened, in the order of arrival.
func (s *Server) DataReceived() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.dataIn...)
}

// DataDropped is how many data packets of the client the server could not open.
func (s *Server) DataDropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataDropped
}

// writeFailed reports a write that failed for a reason other than the end of the link.
func (s *Server) writeFailed(err error) {
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return
	}
	select {
	case <-s.done:
	default:
		s.tb.Errorf("vpntest server: write: %v", err)
	}
}
