package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// hPeerHandler is the stack at the far end of a tunnel: it accepts every TCP flow and hands the
// connection over.
type hPeerHandler struct {
	accepted chan net.Conn
}

func (h *hPeerHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionAccept}
}

func (h *hPeerHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (h *hPeerHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	if err := conn.(*GoConn).HandshakeSuccess(); err != nil { // the SYN-ACK goes once the far end is reached
		conn.Close()
		return
	}
	h.accepted <- conn
}

func (h *hPeerHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

// hGoPair is two Go stacks joined back to back over memory TUNs, as a WireGuard client's stack
// and its server's are joined by the tunnel: the client dials, the peer accepts.
func hGoPair(t *testing.T, dropToPeer func(packet []byte) bool) (client *Go, peer *hPeerHandler, packetsToClient *atomic.Int64) {
	t.Helper()
	const mtu = 1420
	var clientTun, peerTun *MemoryTun
	packetsToClient = new(atomic.Int64)
	forward := func(target **MemoryTun, count *atomic.Int64, drop func([]byte) bool) func([]*buf.Buffer) {
		return func(packets []*buf.Buffer) {
			defer buf.ReleaseMulti(packets)
			frames := make([][]byte, 0, len(packets))
			for _, packet := range packets {
				if drop != nil && drop(packet.Bytes()) {
					continue
				}
				frames = append(frames, packet.Bytes())
			}
			if count != nil {
				count.Add(int64(len(frames)))
			}
			(*target).WritePackets(frames)
		}
	}
	clientTun = NewMemoryTun(MemoryTunOptions{MTU: mtu, Outbound: forward(&peerTun, nil, dropToPeer)})
	peerTun = NewMemoryTun(MemoryTunOptions{MTU: mtu, Outbound: forward(&clientTun, packetsToClient, nil)})
	peer = &hPeerHandler{accepted: make(chan net.Conn, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	start := func(device *MemoryTun, handler Handler) *Go {
		stack, err := NewGo(StackOptions{Context: ctx, Tun: device, TunOptions: Options{MTU: mtu}, UDPTimeout: time.Minute, ICMPTimeout: time.Minute, Handler: handler, Logger: logger.NOP()})
		if err != nil {
			t.Fatal(err)
		}
		if err := stack.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stack.Close() })
		return stack
	}
	start(peerTun, peer)
	client = start(clientTun, nil)
	return client, peer, packetsToClient
}

// A connection the application closed is reset when its peer keeps sending: the data cannot be
// read any more. It used to send its FIN and then take whatever came, acknowledged it and opened
// its window wide: a server that kept sending (a download whose reader went away, forwarded by
// a WireGuard server) sent at full speed into the tunnel for as long as it had data. Over
// loopback that was 1.2 Gbit/s for half a minute after each closed download, which made every
// other connection through the tunnel late by 3 to 9 ms.
func TestH_GoClosedConnectionResetsAPeerThatKeepsSending(t *testing.T) {
	hResetsAPeerThatKeepsSending(t, nil)
}

// The reset that answers a segment takes the sequence number the segment acknowledges: the peer
// takes a reset only at the sequence number it expects. Here the client's FIN is lost, so the
// peer still expects it when its data reaches the closed connection; a reset at the client's own
// next sequence number, past the FIN, was answered with an acknowledgement, that with another
// reset, and so on.
func TestH_GoResetTakesTheAcknowledgedSequence(t *testing.T) {
	var dropped atomic.Bool
	hResetsAPeerThatKeepsSending(t, func(packet []byte) bool {
		tcp := hTCPOf(packet)
		if tcp == nil || tcp.Flags()&header.TCPFlagFin == 0 {
			return false
		}
		dropped.Store(true)
		return true // every FIN: the peer never learns the client closed
	})
	if !dropped.Load() {
		t.Fatal("the client sent no FIN")
	}
}

// hTCPOf is the TCP header of an IPv4 packet, or nil.
func hTCPOf(packet []byte) header.TCP {
	if len(packet) < header.IPv4MinimumSize || header.IPVersion(packet) != header.IPv4Version {
		return nil
	}
	ip := header.IPv4(packet)
	if ip.TransportProtocol() != header.TCPProtocolNumber || int(ip.HeaderLength()) > len(packet)-header.TCPMinimumSize {
		return nil
	}
	return header.TCP(packet[ip.HeaderLength():])
}

func hResetsAPeerThatKeepsSending(t *testing.T, dropToPeer func(packet []byte) bool) {
	t.Helper()
	client, peer, packetsToClient := hGoPair(t, dropToPeer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, netip.MustParseAddr("10.7.0.2"), netip.MustParseAddrPort("192.0.2.1:10900"))
	if err != nil {
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-peer.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the peer saw no connection")
	}
	defer server.Close()
	// the peer sends 8 MB, waits until the client has read them all and closed, and then sends
	// as fast as it can until a write fails: the client closes with nothing unread, the close
	// that sent a FIN and went on taking data
	const first = 8 << 20
	resume := make(chan struct{})
	writeErr := make(chan error, 1)
	go func() {
		chunk := make([]byte, 64<<10)
		for sent := 0; ; sent += len(chunk) {
			if sent == first {
				<-resume
			}
			if _, err := server.Write(chunk); err != nil {
				writeErr <- err
				return
			}
		}
	}()
	buffer := make([]byte, 256<<10)
	for read := 0; read < first; {
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		read += n
	}
	atClose := packetsToClient.Load()
	conn.Close()
	closedAt := time.Now()
	close(resume)
	select {
	case err := <-writeErr:
		took, sent := time.Since(closedAt), packetsToClient.Load()-atClose
		t.Logf("the peer was reset %v after the close, with %d packets to the client", took, sent)
		if took > 500*time.Millisecond || sent > 5000 {
			t.Fatalf("the peer was reset only %v after the close, after %d packets to the client", took, sent)
		}
		var netErr net.Error
		if !errors.Is(err, net.ErrClosed) && !errors.As(err, &netErr) && err == nil {
			t.Fatalf("the peer's write failed with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("the peer still sends 3 s after the client closed: %d packets went to the client", packetsToClient.Load())
	}
	// and the traffic stops: what was in flight, and nothing more
	time.Sleep(200 * time.Millisecond)
	before := packetsToClient.Load()
	time.Sleep(500 * time.Millisecond)
	if moved := packetsToClient.Load() - before; moved > 10 {
		t.Fatalf("%d packets went to the client in half a second after the reset", moved)
	}
}
