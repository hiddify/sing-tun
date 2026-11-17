package tun

import "net/netip"

// addressHolder is an address that another interface holds.
type addressHolder struct {
	Interface string
	Up        bool
	Prefix    netip.Prefix
}

// conflictingAddresses sorts the holders of the tunnel's addresses. Windows refuses to
// give the tunnel an address another interface already has. An interface that is not up
// (an adapter left disconnected, by us or another VPN) keeps it for nothing, so it is
// stale and can be taken off. An interface that is up is in use, so it is live and the
// address is not ours to take.
func conflictingAddresses(addresses []netip.Prefix, holders []addressHolder) (stale []int, live []int) {
	wanted := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		wanted[address.Addr().Unmap()] = true
	}
	for i, holder := range holders {
		if !wanted[holder.Prefix.Addr().Unmap()] {
			continue
		}
		if holder.Up {
			live = append(live, i)
		} else {
			stale = append(stale, i)
		}
	}
	return
}
