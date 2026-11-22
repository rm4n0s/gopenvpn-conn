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

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// serverData is the data channel of the server: the keys of the TLS exporter,
// used the other way round from the client.
type serverData struct {
	id   uint8
	ch   datachan.Channel
	rbuf []byte     // the loop goroutine only
	mu   sync.Mutex // Seal: SendData and the echo run apart
}

// setupData makes the data channel from the TLS session, once the key exchange is
// done. A failure fails the test: the server of a test has no reason to refuse.
func (s *Server) setupData(conn *tls.Conn, ks *serverKS) {
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
	if ks.id == 0 && s.opts.DynamicTLSCrypt {
		s.setupDynamic(&state)
	}
	header := datachan.Header{HasPeerID: !s.opts.DataV1, KeyID: ks.id}
	var ch datachan.Channel
	if s.opts.Epoch {
		ch, err = datachan.NewEpochChannel(cipher, &dk.ServerToClient, &dk.ClientToServer, header,
			datachan.EpochOptions{UsageLimit: s.opts.EpochUsageLimit})
	} else {
		ch, err = datachan.NewChannel(cipher, &dk.ServerToClient, &dk.ClientToServer, header, datachan.ReceiverOptions{})
	}
	if err != nil {
		s.tb.Errorf("vpntest server: %v", err)
		return
	}
	s.mu.Lock()
	ks.data, ks.established = &serverData{id: ks.id, ch: ch}, time.Now()
	s.order = append(s.order, ks)
	s.history = append(s.history, ks.id)
	s.mu.Unlock()
}

// setupDynamic makes the protection of the renegotiations from the TLS session of
// the first key, the way the client does, with the server's side of the keys.
func (s *Server) setupDynamic(state *tls.ConnectionState) {
	material, err := state.ExportKeyingMaterial(ctrlwrap.DynamicLabel, nil, keys.StaticKeySize)
	if err != nil {
		s.tb.Errorf("vpntest server: exporting the dynamic tls-crypt key: %v", err)
		return
	}
	w, err := ctrlwrap.NewDynamic(material, s.opts.StaticKey, true, time.Now)
	if err != nil {
		s.tb.Errorf("vpntest server: %v", err)
		return
	}
	s.mu.Lock()
	s.dyn = w
	s.mu.Unlock()
}

// sendKey is the data channel the server seals with: the newest key once its delay has
// passed, else the one before it.
func (s *Server) sendKey() *serverData {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.order)
	if n == 0 {
		return nil
	}
	newest := s.order[n-1]
	if n > 1 && time.Since(newest.established) < s.opts.SwitchDelay {
		return s.order[n-2].data
	}
	return newest.data
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
	var d *serverData
	if ks := s.getKS(raw[0] & 0x07); ks != nil {
		s.mu.Lock()
		d = ks.data
		s.mu.Unlock()
	}
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
	if bytes.Equal(plain, pingString) {
		s.mu.Lock()
		s.pings++
		s.mu.Unlock()
		return
	}
	if bytes.Equal(plain, occExitPacket) {
		s.mu.Lock()
		s.occExits++
		s.mu.Unlock()
		return
	}
	packet := bytes.Clone(plain)
	s.mu.Lock()
	s.dataIn = append(s.dataIn, packet)
	s.mu.Unlock()
	if s.opts.OnData != nil {
		s.opts.OnData(packet)
	}
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
	d := s.sendKey()
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

// SendDataWithKey is SendData with the key of a key id that the server holds, not the
// one that it seals with now: for the tests of the old key. It fails the test when the
// server has no such key.
func (s *Server) SendDataWithKey(id uint8, payload []byte) ([]byte, error) {
	var d *serverData
	if ks := s.getKS(id); ks != nil {
		s.mu.Lock()
		d = ks.data
		s.mu.Unlock()
	}
	if d == nil {
		s.tb.Errorf("vpntest server: no key with the key id %d", id)
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

// SkipData seals a packet with the server's key and does not send it: its packet
// id is used up and never arrives. A real server with the kernel data channel
// (DCO) does that on a TCP link when its socket is full (SPEC §21 O31).
func (s *Server) SkipData() error {
	d := s.sendKey()
	if d == nil {
		s.tb.Error("vpntest server: SkipData before the key exchange is done")
		return nil
	}
	d.mu.Lock()
	_, err := d.ch.Seal(nil, []byte{0x45})
	d.mu.Unlock()
	return err
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

// pingString is the payload of OpenVPN's keepalive ping (ping.c ping_string).
var pingString = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// occExitPacket is the plaintext of the exit message of the data channel: the OCC
// magic and the byte OCC_EXIT (occ.c).
var occExitPacket = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
	6,
}

// OCCExits is how many exit messages of the data channel the server has received;
// they are not in DataReceived.
func (s *Server) OCCExits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.occExits
}

// Exits is how many EXIT messages of the control channel the server has received.
func (s *Server) Exits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exits
}

// SendOCCExit sends the client the exit message of the data channel.
func (s *Server) SendOCCExit() error {
	_, err := s.SendData(occExitPacket)
	return err
}

// Pings is how many keepalive pings the server has received from the client; they
// are not in DataReceived.
func (s *Server) Pings() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pings
}

// SendPing sends the client a keepalive ping.
func (s *Server) SendPing() error {
	_, err := s.SendData(pingString)
	return err
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
