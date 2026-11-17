package tun

import (
	"net/netip"
	"testing"
)

func TestH_ConflictingAddresses(t *testing.T) {
	addresses := []netip.Prefix{
		netip.MustParsePrefix("172.19.0.1/28"),
		netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
	}
	holders := []addressHolder{
		{Interface: "Ethernet", Up: true, Prefix: netip.MustParsePrefix("192.168.1.10/24")},
		{Interface: "tun0", Up: false, Prefix: netip.MustParsePrefix("172.19.0.1/30")},
		{Interface: "other-vpn", Up: true, Prefix: netip.MustParsePrefix("fdfe:dcba:9876::1/64")},
		{Interface: "Wi-Fi", Up: false, Prefix: netip.MustParsePrefix("172.19.0.2/28")},
	}
	stale, live := conflictingAddresses(addresses, holders)
	if len(stale) != 1 || holders[stale[0]].Interface != "tun0" {
		t.Fatalf("stale = %v, want only tun0", stale)
	}
	if len(live) != 1 || holders[live[0]].Interface != "other-vpn" {
		t.Fatalf("live = %v, want only other-vpn", live)
	}
}
