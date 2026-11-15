package tun

import (
	"net"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// A connection the application closed is reset when its peer sends it more data.
//
// Close sends a FIN when nothing waits to be read, and the connection lingers until the peer
// closes too. The peer may go on sending meanwhile: a server whose download the application
// stopped reading keeps sending until it is told. The data that came was taken, thrown away and
// acknowledged, with the window opened wide, so the peer was never told and sent at full speed
// for as long as it had data. Through a WireGuard tunnel to a server that forwards a download,
// that was 1.2 Gbit/s for half a minute after each download the application closed, and every
// other connection through the tunnel was late by 3 to 9 ms behind it.
//
// RFC 1122 4.2.2.13 asks for a reset when data arrives after the application closed the
// connection, to show that it was lost, and Linux and gVisor send one. So does this stack now.
//
// A reset is taken only at the sequence number its receiver expects next (RFC 5961). Our own
// next sequence number is past it while data or a FIN of ours is still on its way, and the peer
// answers such a reset with an acknowledgement; a connection that lingers after an abort replied
// to that with another reset, and the two went back and forth. So the reset that answers a
// segment takes the segment's acknowledgement number, as RFC 793 asks of a closed connection.

// resetOnData resets a connection the application closed, whose peer sent it new data.
func (e *goEngine) resetOnData(conn *GoConn, tcpHdr header.TCP) {
	e.sendResetFor(conn, tcpHdr)
	e.detachConn(conn, net.ErrClosed, goDeathAbortLinger)
}

// sendResetFor answers the segment tcpHdr with a reset at the sequence number the segment
// acknowledges, or at our next one when it acknowledges nothing we sent.
func (e *goEngine) sendResetFor(conn *GoConn, tcpHdr header.TCP) bool {
	if conn.state == goTCPSynSent || len(tcpHdr) < header.TCPMinimumSize || tcpHdr.Flags()&header.TCPFlagAck == 0 {
		return e.sendReset(conn)
	}
	offset := conn.sendOffset(tcpHdr.AckNumber())
	if offset < 0 || uint64(offset) > conn.sendNext() {
		return e.sendReset(conn)
	}
	segment := goSegment{offset: uint64(offset), flags: header.TCPFlagRst | header.TCPFlagAck}
	return e.writeConnControl(conn, &segment)
}
