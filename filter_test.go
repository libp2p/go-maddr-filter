package filter

import (
	"net"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestFilterBlocking(t *testing.T) {
	f := NewFilters()

	_, ipnet, _ := net.ParseCIDR("0.1.2.3/24")
	f.AddDialFilter(ipnet)
	filters := f.Filters()
	if len(filters) != 1 {
		t.Fatal("Expected only 1 filter")
	}
	f.Remove(filters[0])

	for _, cidr := range []string{
		"1.2.3.0/24",
		"4.3.2.1/32",
		"fd00::/8",
		"fc00::1/128",
	} {
		_, ipnet, _ := net.ParseCIDR(cidr)
		f.AddDialFilter(ipnet)
	}

	// These addresses should all be blocked
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
		"",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to not be blocked", addr)
		}
	}
}

func TestFilterWhitelisting(t *testing.T) {
	f := NewFilters()

	// Add default reject filter
	f.RejectByDefault = true

	// Add a whitelist
	_, ipnet, _ := net.ParseCIDR("1.2.3.0/24")
	f.AddAllowFilter(ipnet)

	// That /24 should now be allowed
	for _, addr := range []string{
		"/ip4/1.2.3.1/tcp/123",
		"/ip4/1.2.3.254/tcp/123",
		"/ip4/1.2.3.254/udp/321",
	} {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be whitelisted", addr)
		}
	}

	// No policy matches these maddrs, they should be blocked by default
	for _, blocked := range []string{
		"/ip4/1.2.4.4/tcp/123",
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
}

func TestFiltersRemoveRules(t *testing.T) {
	f := NewFilters()

	ips := []string{
		"/ip4/1.2.3.1/tcp/123",
		"/ip4/1.2.3.254/tcp/123",
	}

	// Add default reject filter
	f.RejectByDefault = true

	// Add whitelisting
	_, ipnet, _ := net.ParseCIDR("1.2.3.0/24")
	f.AddAllowFilter(ipnet)

	// these are all whitelisted, should be OK
	for _, addr := range ips {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be whitelisted", addr)
		}
	}

	// Test removing the filter. It'll remove multiple, so make a dupe &
	// a complement
	f.AddDialFilter(ipnet)

	// Show that they all apply, these are now blacklisted & should fail
	for _, addr := range ips {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if !f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be blacklisted", addr)
		}
	}

	// remove those rules
	f.Remove(ipnet)

	// our default is reject, so the 1.2.3.0/24 should be rejected now,
	// along with everything else
	for _, addr := range ips {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.Error(err)
		}
		if !f.AddrBlocked(maddr) {
			t.Fatalf("expected %s to be blocked", addr)
		}
	}
}
