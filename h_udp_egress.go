package tun

// memberPort is the port an egress member is bound to.
//
// A member was bound to the pool's port, the port of the bind it sends for, on its interface's
// address. Windows takes a UDP socket bound to an explicit port for a server and asks the user to
// allow the app through its firewall ("Windows Firewall has blocked some features of Hiddify Core"),
// although a client's member only sends to its peers and reads their answers. A socket on port 0
// is never asked about. So the members of a pool for a bind on an ephemeral port (a WireGuard
// client without listen_port) take their own ephemeral ports: a peer sees another source port when
// a packet leaves through another interface, as it does when the network changes, and answers it.
// A pool for a port asked for (a server) still binds every member to it.
func (p *UDPEgressPool) memberPort() uint16 {
	if p.ephemeralPorts {
		return 0
	}
	return p.port
}
