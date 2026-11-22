// SPDX-License-Identifier: GPL-2.0-only

// Package vpnnet is a userspace network over an *openvpn.Conn: it makes TCP and UDP
// connections, listeners and packet connections that go through the VPN, with no TUN
// device, no root and no change to the machine.
//
// A Net runs a TCP/IP stack (gVisor's tcpip, the only place where this module
// imports it) whose one interface is the tunnel: the packets that the stack sends
// are written to the Conn, and the packets that the Conn reads are given to the
// stack. The connections that DialContext, Listen and ListenPacket return are the
// ones of gVisor's gonet package behind the interfaces of package net: a net.Conn, a
// net.Listener and a net.PacketConn. No type of gVisor is in the API.
//
// A Net takes over the Read of its Conn: nothing else may read the Conn while the
// Net is open.
package vpnnet
