package tun

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

// loopbackSpec is an egress member spec on the loopback interface, which every test machine has.
func loopbackSpec(t *testing.T) udpEgressSpec {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagLoopback != 0 {
			return udpEgressSpec{
				interfaceIndex: networkInterface.Index,
				interfaceName:  networkInterface.Name,
				prefix:         netip.MustParsePrefix("127.0.0.1/8"),
			}
		}
	}
	t.Skip("no loopback interface")
	return udpEgressSpec{}
}

// A pool for a bind on an ephemeral port binds its members to port 0: Windows asks the user to
// allow the app through its firewall for a UDP socket bound to an explicit port, the bind's own
// port on each interface address before. A pool for a port asked for (a server's listen_port)
// still binds its members to that port.
func TestH_UDPEgressMemberPort(t *testing.T) {
	spec := loopbackSpec(t)
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	listener.Close()

	for _, ephemeral := range []bool{true, false} {
		var bound []string
		pool := NewUDPEgressPool(UDPEgressPoolOptions{
			Logger:          logger.NOP(),
			InterfaceFinder: control.NewDefaultInterfaceFinder(),
			EphemeralPorts:  ephemeral,
			Control: func(network, address string, conn syscall.RawConn) error {
				bound = append(bound, address)
				return nil
			},
		})
		pool.port = port
		conn, err := pool.listenMember(spec)
		if err != nil {
			t.Skipf("cannot open a member on %s: %v", spec.interfaceName, err)
		}
		conn.Close()
		want := ":" + strconv.Itoa(int(port))
		if ephemeral {
			want = ":0"
		}
		if len(bound) != 1 || !strings.HasSuffix(bound[0], want) {
			t.Fatalf("ephemeral %v: member bound to %q, want port %s", ephemeral, bound, want)
		}
	}
}
