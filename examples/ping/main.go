// SPDX-License-Identifier: GPL-2.0-only

// Command ping connects to an OpenVPN server and sends ICMP echo requests through
// the tunnel with no root and no change to the machine. It uses only the public API
// of package openvpn: the tunnel is a net.Conn of IP packets, and the program builds
// and reads the packets itself.
//
//	go run ./examples/ping -server vpn.example.com:1194 -ca ca.crt -cert client.crt -key client.key -tls-crypt ta.key
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

func main() {
	server := flag.String("server", "", "address of the server, host:port")
	network := flag.String("proto", "udp", "udp or tcp")
	caFile := flag.String("ca", "", "the CA certificate of the server (PEM)")
	certFile := flag.String("cert", "", "the client certificate (PEM)")
	keyFile := flag.String("key", "", "the key of the client certificate (PEM)")
	cryptFile := flag.String("tls-crypt", "", "the tls-crypt key file, when the server has one")
	target := flag.String("target", "", "the address to ping; the tunnel address of the server when empty")
	count := flag.Int("count", 4, "how many requests to send")
	flag.Parse()
	if *server == "" || *caFile == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *network, *caFile, *certFile, *keyFile, *cryptFile, *target, *count); err != nil {
		log.Fatal(err)
	}
}

func run(server, network, caFile, certFile, keyFile, cryptFile, target string, count int) (err error) {
	roots, err := loadRoots(caFile)
	if err != nil {
		return err
	}
	opts := openvpn.TLSOptions{RootCAs: roots, RemoteCertTLSServer: true}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		opts.Certificates = []tls.Certificate{cert}
	}
	config := &openvpn.Config{TLS: openvpn.NewTLSConfig(opts)}
	if cryptFile != "" {
		key, err := os.ReadFile(cryptFile)
		if err != nil {
			return err
		}
		if config.ControlWrap, err = openvpn.NewTLSCrypt(key); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := openvpn.Dial(ctx, network, server, config)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	state := conn.ConnectionState()
	me, dst, err := pingAddresses(state.Addrs, state.Gateway, target)
	if err != nil {
		return err
	}
	fmt.Printf("connected: address %v, cipher %s, MTU %d; pinging %v\n", state.Addrs[0], state.Cipher, state.MTU, dst)

	const id = 0x4f50
	buf := make([]byte, state.MTU)
	for seq := 1; seq <= count; seq++ {
		payload := []byte(fmt.Sprintf("ping %04d from gopenvpn-conn", seq))
		start := time.Now()
		if _, err := conn.Write(echoRequest(me, dst, id, uint16(seq), payload)); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(start.Add(3 * time.Second)); err != nil {
			return err
		}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "no reply to request %d\n", seq)
				return err
			}
			src, gotSeq, data, ok := echoReply(buf[:n], id)
			if !ok || gotSeq != uint16(seq) {
				continue // another packet, or a late reply
			}
			fmt.Printf("%d bytes from %v: seq=%d time=%v payload=%q\n", n-28, src, gotSeq, time.Since(start).Round(10*time.Microsecond), data)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// loadRoots reads the certificates of the CA file.
func loadRoots(caFile string) (*x509.CertPool, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New(tagNoCertificate, "the CA file has no certificate", "file", caFile)
	}
	return roots, nil
}

// pingAddresses chooses the two addresses of the ping: the first address that the
// server gave to the client, and the address to ping (target when it is not empty,
// else the server's own address in the tunnel).
func pingAddresses(addrs []netip.Prefix, gateway netip.Addr, target string) (me, dst netip.Addr, err error) {
	if len(addrs) == 0 || !addrs[0].Addr().Is4() {
		return me, dst, errors.New(tagNoAddress, "the server gave no IPv4 address to the client", "addresses", fmt.Sprint(addrs))
	}
	me, dst = addrs[0].Addr(), gateway
	if target != "" {
		if dst, err = netip.ParseAddr(target); err != nil {
			return me, dst, errors.NewErr(tagBadTarget, err).SetMetadata("target", target)
		}
	}
	if !dst.Is4() {
		return me, dst, errors.New(tagNoTarget, "there is no IPv4 address to ping: use -target")
	}
	return me, dst, nil
}

// echoRequest is an IPv4 packet with an ICMP echo request.
func echoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8, 8+len(payload))
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	icmp = append(icmp, payload...)
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))

	ip := make([]byte, 20, 20+len(icmp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16((20+len(icmp))&0xffff)) // a ping is far below 64 KiB
	ip[8] = 64                                                        // the TTL
	ip[9] = 1                                                         // ICMP
	s, d := src.As4(), dst.As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	return append(ip, icmp...)
}

// echoReply reads an IPv4 packet with an ICMP echo reply with the id, and returns
// its source, its sequence number and its payload.
func echoReply(p []byte, id uint16) (src netip.Addr, seq uint16, payload []byte, ok bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 {
		return src, 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+8 || p[ihl] != 0 || binary.BigEndian.Uint16(p[ihl+4:]) != id {
		return src, 0, nil, false
	}
	src = netip.AddrFrom4([4]byte(p[12:16]))
	return src, binary.BigEndian.Uint16(p[ihl+6:]), p[ihl+8:], true
}

// checksum is the Internet checksum of RFC 1071.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum & 0xffff)
}

const (
	tagNoCertificate = "NoCertificate"
	tagNoAddress     = "NoAddress"
	tagNoTarget      = "NoTarget"
	tagBadTarget     = "BadTarget"
)
