package tun

import (
	"errors"
	"net/netip"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// setIPAddresses gives the tunnel its addresses. Windows refuses an address another
// interface already holds with ERROR_OBJECT_ALREADY_EXISTS. A holder that is not up keeps
// the address for nothing: take it off and try again, as WireGuard for Windows does. A
// holder that is up is in use, so name it in the error instead of taking its address.
func (t *NativeTun) setIPAddresses(luid winipcfg.LUID, family winipcfg.AddressFamily, addresses []netip.Prefix) error {
	err := luid.SetIPAddressesForFamily(family, addresses)
	if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	interfaces, listErr := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if listErr != nil {
		return err
	}
	var (
		holders     []addressHolder
		holderLUIDs []winipcfg.LUID
	)
	for _, iface := range interfaces {
		if iface.LUID == luid {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip, ok := netip.AddrFromSlice(address.Address.IP())
			if !ok {
				continue
			}
			holders = append(holders, addressHolder{
				Interface: iface.FriendlyName(),
				Up:        iface.OperStatus == winipcfg.IfOperStatusUp,
				Prefix:    netip.PrefixFrom(ip.Unmap(), int(address.OnLinkPrefixLength)),
			})
			holderLUIDs = append(holderLUIDs, iface.LUID)
		}
	}
	stale, live := conflictingAddresses(addresses, holders)
	for _, i := range stale {
		if t.options.Logger != nil {
			t.options.Logger.Warn("removing the stale address ", holders[i].Prefix, " from the disconnected interface ", holders[i].Interface)
		}
		_ = holderLUIDs[i].DeleteIPAddress(holders[i].Prefix)
	}
	if len(stale) > 0 {
		err = luid.SetIPAddressesForFamily(family, addresses)
		if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return err
		}
	}
	if len(live) > 0 {
		holder := holders[live[0]]
		return E.Cause(err, holder.Prefix.Addr(), " is in use by the interface ", holder.Interface, "; another VPN or a Hiddify core that is still running holds it")
	}
	return err
}
