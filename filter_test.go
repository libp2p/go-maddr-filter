package filter

import (
	"net"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestFilter(t *testing.T) {
	f := NewFilters()
	for _, cidr := range []string{
		"1.2.3.0/24",
		"4.3.2.1/32",
		"fd00::/8",
		"fc00::1/128",
	} {
		_, ipnet, _ := net.ParseCIDR(cidr)
		f.AddDialFilter(ipnet)
	}

	for _, blocked := range []string{
		"/ip4/1.2.3.4/tcp/123",
		"/ip4/4.3.2.1/udp/123",
		"/ip6/fd00::2/tcp/321",
		"/ip6/fc00::1/udp/321",
	} {
		maddr, err := ma.NewMultiaddr(blocked)
		if err != nil {
			t.Error(err)
		}
		if !f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be blocked", blocked)
		}
	}

	// test that other net intervals are not blocked
	for _, addr := range []string{
		"/ip4/1.2.4.1/tcp/123",
		"/ip4/4.3.2.2/udp/123",
		"/ip6/fe00::1/tcp/321",
		"/ip6/fc00::2/udp/321",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to not be blocked", addr)
		}
	}

	// test whitelisting
	_, ipnet, _ := net.ParseCIDR("1.2.3.0/24")
	f.AddAllowFilter(ipnet)
	for _, addr := range []string{
		"/ip4/1.2.3.1/tcp/123",
		"/ip4/1.2.3.254/tcp/123",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be whitelisted", addr)
		}
	}

	// test default-deny
	// from above we're allowing "1.2.3.0/24
	f.RejectByDefault = true

	// these are all whitelisted, should be OK
	f.AddAllowFilter(ipnet)
	for _, addr := range []string{
		"/ip4/1.2.3.1/tcp/123",
		"/ip4/1.2.3.254/tcp/123",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be whitelisted", addr)
		}
	}

	// these are not whitelisted, should be rejected now
	for _, addr := range []string{
		"/ip4/1.2.4.1/tcp/123",
		"/ip4/4.3.2.2/udp/123",
		"/ip6/fe00::1/tcp/321",
		"/ip6/fc00::2/udp/321",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if !f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be blocked", addr)
		}
	}

	// Test removing the filter. It'll remove multiple, so make a dupe &
	// a complement
	f.AddAllowFilter(ipnet)
	f.AddDialFilter(ipnet)

	f.Remove(ipnet)
	// our default is reject, so the 1.2.3.0/24 should be rejected now
	for _, addr := range []string{
		"/ip4/1.2.3.1/tcp/123",
		"/ip4/4.3.3.254/udp/123",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if !f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be blocked", addr)
		}
	}
}
